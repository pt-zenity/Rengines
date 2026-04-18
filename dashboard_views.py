from datetime import timedelta
import io
import json
import logging
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import threading
import time

from django.contrib import messages
from django.http import FileResponse, Http404
from django.utils.timezone import now as django_now
from django.contrib.auth import get_user_model, update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.dispatch import receiver
from django.http import HttpResponseBadRequest, HttpResponseRedirect, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.template.defaultfilters import slugify
from django.urls import reverse
from django.utils import timezone
from rolepermissions.decorators import has_permission_decorator
from rolepermissions.roles import assign_role, clear_roles

from dashboard.forms import ProjectForm
from dashboard.models import NetlasAPIKey, OpenAiAPIKey, Project, UserAPIKey
from dashboard.utils import get_user_groups, get_user_projects
from reNgine.definitions import FOUR_OH_FOUR_URL, PERM_MODIFY_SYSTEM_CONFIGURATIONS
from startScan.models import (
    CountryISO,
    EndPoint,
    IpAddress,
    Port,
    ScanActivity,
    ScanHistory,
    Subdomain,
    SubScan,
    Technology,
    Vulnerability,
)
from targetApp.models import Domain


logger = logging.getLogger(__name__)


def index(request, slug):
    try:
        project = Project.get_from_slug(slug)
    except Project.DoesNotExist:
        return HttpResponseRedirect(reverse("page_not_found"))

    # Get activity feed
    activity_feed = (
        ScanActivity.objects.filter(scan_of__domain__project=project)
        .select_related("scan_of", "scan_of__domain")
        .order_by("-time")[:50]
    )

    last_week = timezone.now() - timedelta(days=7)
    date_range = [last_week + timedelta(days=i) for i in range(7)]

    # Get timeline data from each model
    timeline_data = {
        "targets": Domain.get_project_timeline(project, date_range),
        "subdomains": Subdomain.get_project_timeline(project, date_range),
        "vulns": Vulnerability.get_project_timeline(project, date_range),
        "endpoints": EndPoint.get_project_timeline(project, date_range),
        "scans": {
            "pending": ScanHistory.get_project_timeline(project, date_range, status=0),
            "running": ScanHistory.get_project_timeline(project, date_range, status=1),
            "completed": ScanHistory.get_project_timeline(project, date_range, status=2),
            "failed": ScanHistory.get_project_timeline(project, date_range, status=3),
        },
        "subscans": {
            "pending": SubScan.get_project_timeline(project, date_range, status=-1),
            "running": SubScan.get_project_timeline(project, date_range, status=1),
            "completed": SubScan.get_project_timeline(project, date_range, status=2),
            "failed": SubScan.get_project_timeline(project, date_range, status=0),
            "aborted": SubScan.get_project_timeline(project, date_range, status=3),
            "finalizing": SubScan.get_project_timeline(project, date_range, status=4),
        },
    }

    # Get project data from all models
    ip_data = IpAddress.get_project_data(project)
    port_data = Port.get_project_data(project)
    tech_data = Technology.get_project_data(project)
    country_data = CountryISO.get_project_data(project)
    vulnerability_data = Vulnerability.get_project_data(project)

    # Get all counts using project-specific methods
    domain_counts = Domain.get_project_counts(project)
    subdomain_counts = Subdomain.get_project_counts(project)
    endpoint_counts = EndPoint.get_project_counts(project)
    scan_history_counts = ScanHistory.get_project_counts(project)
    subscan_counts = SubScan.get_project_counts(project)

    context = {
        "dashboard_data_active": "active",
        "domain_count": domain_counts["total"],
        "scan_count": scan_history_counts,
        "subscan_count": subscan_counts,
        "subdomain_count": subdomain_counts["total"],
        "subdomain_with_ip_count": subdomain_counts["with_ip"],
        "alive_count": subdomain_counts["alive"],
        "endpoint_count": endpoint_counts["total"],
        "endpoint_alive_count": endpoint_counts["alive"],
        "info_count": subdomain_counts["vuln_info"],
        "low_count": subdomain_counts["vuln_low"],
        "medium_count": subdomain_counts["vuln_medium"],
        "high_count": subdomain_counts["vuln_high"],
        "critical_count": subdomain_counts["vuln_critical"],
        "unknown_count": subdomain_counts["vuln_unknown"],
        "total_vul_count": subdomain_counts["total_vuln_count"],
        "total_vul_ignore_info_count": subdomain_counts["total_vuln_ignore_info_count"],
        "vulnerability_feed": vulnerability_data["feed"],
        "activity_feed": activity_feed,
        "total_ips": ip_data["total_count"],
        "most_used_ip": ip_data["most_used"],
        "most_used_port": port_data["most_used"],
        "most_used_tech": tech_data["most_used"],
        "asset_countries": country_data["asset_countries"],
        "targets_in_last_week": timeline_data["targets"],
        "subdomains_in_last_week": timeline_data["subdomains"],
        "vulns_in_last_week": timeline_data["vulns"],
        "endpoints_in_last_week": timeline_data["endpoints"],
        "scans_in_last_week": timeline_data["scans"],
        "subscans_in_last_week": timeline_data["subscans"],
        "most_common_cve": vulnerability_data["most_common_cve"],
        "most_common_cwe": vulnerability_data["most_common_cwe"],
        "most_common_tags": vulnerability_data["most_common_tags"],
    }

    return render(request, "dashboard/index.html", context)


def profile(request):
    if request.method == "POST":
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)
            messages.success(request, "Your password was successfully changed!")
            return redirect("profile")
        else:
            messages.error(request, "Please correct the error below.")
    else:
        form = PasswordChangeForm(request.user)
    return render(request, "dashboard/profile.html", {"form": form})


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def admin_interface(request):
    User = get_user_model()  # noqa: N806
    users = User.objects.all().order_by("date_joined")
    return render(request, "dashboard/admin.html", {"users": users})


class UserModificationError(Exception):
    def __init__(self, message, status_code=403):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)


def check_user_modification_permissions(current_user, target_user, mode):
    """Check if current user has permission to modify target user."""
    if not target_user:
        raise UserModificationError("User ID not provided", 404)

    # Security checks for superusers and sys_admins
    if target_user.is_superuser and not current_user.is_superuser:
        raise UserModificationError("Only superadmin can modify another superadmin")

    # Prevent self-modification for both superusers and sys_admins
    if (
        current_user == target_user
        and mode in ["delete", "change_status"]
        and (current_user.is_superuser or get_user_groups(current_user) == "sys_admin")
    ):
        raise UserModificationError("Administrators cannot delete or deactivate themselves")


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def admin_interface_update(request):
    mode = request.GET.get("mode")
    method = request.method
    target_user = get_user_from_request(request)

    try:
        if mode and mode != "create":
            check_user_modification_permissions(request.user, target_user, mode)

        # Check if the request is for user creation
        if method == "POST" and mode == "create":
            return handle_post_request(request, mode, None)

        if method == "GET":
            return handle_get_request(request, mode, target_user)
        elif method == "POST":
            return handle_post_request(request, mode, target_user)

    except UserModificationError as e:
        return JsonResponse({"status": False, "error": e.message}, status=e.status_code)


def get_user_from_request(request):
    if user_id := request.GET.get("user"):
        User = get_user_model()  # noqa: N806
        return User.objects.filter(id=user_id).first()  # Use first() to avoid exceptions
    return None


def handle_get_request(request, mode, user):
    if mode == "change_status":
        user.is_active = not user.is_active
        user.save()
        if user.is_active:
            messages.add_message(request, messages.INFO, f"User {user.username} successfully activated.")
        else:
            messages.add_message(request, messages.INFO, f"User {user.username} successfully deactivated.")
        return HttpResponseRedirect(reverse("admin_interface"))
    return HttpResponseBadRequest(reverse("admin_interface"), status=400)


def handle_post_request(request, mode, user):
    if mode == "delete":
        return handle_delete_user(request, user)
    elif mode == "update":
        return handle_update_user(request, user)
    elif mode == "create":
        return handle_create_user(request)
    return JsonResponse({"status": False, "error": "Invalid mode"}, status=400)


def handle_delete_user(request, user):
    try:
        user.delete()
        messages.add_message(request, messages.INFO, f"User {user.username} successfully deleted.")
        return JsonResponse({"status": True})
    except (ValueError, KeyError) as e:
        logger.error("Error deleting user: %s", e)
        return JsonResponse({"status": False, "error": "An error occurred while deleting the user"})


def handle_update_user(request, user):
    try:
        response = json.loads(request.body)
        role = response.get("role")
        change_password = response.get("change_password")
        projects = response.get("projects", [])

        clear_roles(user)
        assign_role(user, role)
        if change_password:
            user.set_password(change_password)

        # Update projects
        user.projects.clear()  # Remove all existing projects
        for project_id in projects:
            project = Project.objects.get(id=project_id)
            user.projects.add(project)

        user.save()
        return JsonResponse({"status": True})
    except (ValueError, KeyError) as e:
        logger.error("Error updating user: %s", e)
        return JsonResponse({"status": False, "error": "An error occurred while updating the user"})


def handle_create_user(request):
    try:
        response = json.loads(request.body)
        if not response.get("password"):
            return JsonResponse({"status": False, "error": "Empty passwords are not allowed"})

        User = get_user_model()  # noqa: N806
        user = User.objects.create_user(username=response.get("username"), password=response.get("password"))
        assign_role(user, response.get("role"))

        # Add projects
        projects = response.get("projects", [])
        for project_id in projects:
            project = Project.objects.get(id=project_id)
            user.projects.add(project)

        return JsonResponse({"status": True})
    except (ValueError, KeyError) as e:
        logger.error("Error creating user: %s", e)
        return JsonResponse({"status": False, "error": "An error occurred while creating the user"})


@receiver(user_logged_out)
def on_user_logged_out(sender, request, **kwargs):
    messages.add_message(
        request, messages.INFO, "You have been successfully logged out. Thank you " + "for using reNgine-ng."
    )


@receiver(user_logged_in)
def on_user_logged_in(sender, request, **kwargs):
    user = kwargs.get("user")
    messages.add_message(request, messages.INFO, "Hi @" + user.username + " welcome back!")


def search(request):
    return render(request, "dashboard/search.html")


def four_oh_four(request):
    return render(request, "404.html")


def projects(request):
    context = {"projects": get_user_projects(request.user)}
    return render(request, "dashboard/projects.html", context)


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def delete_project(request, id):
    obj = get_object_or_404(Project, id=id)
    if request.method == "POST":
        obj.delete()
        response_data = {"status": "true"}
        messages.add_message(request, messages.INFO, "Project successfully deleted!")
    else:
        response_data = {"status": "false"}
        messages.add_message(request, messages.ERROR, "Oops! Project could not be deleted!")
    return JsonResponse(response_data)


def onboarding(request):
    error = ""
    if request.method == "POST":
        project_name = request.POST.get("project_name")
        slug = slugify(project_name)
        create_username = request.POST.get("create_username")
        create_password = request.POST.get("create_password")
        create_user_role = request.POST.get("create_user_role")
        key_openai = request.POST.get("key_openai")
        key_netlas = request.POST.get("key_netlas")

        insert_date = timezone.now()

        try:
            Project.objects.create(name=project_name, slug=slug, insert_date=insert_date)
        except Exception as e:
            logger.error(f" Could not create project, Error: {e}")
            error = "Could not create project, check logs for more details"

        try:
            if create_username and create_password and create_user_role:
                User = get_user_model()  # noqa: N806
                user = User.objects.create_user(username=create_username, password=create_password)
                assign_role(user, create_user_role)
        except Exception as e:
            logger.error(f"Could not create User, Error: {e}")
            error = "Could not create User, check logs for more details"

        if key_openai:
            openai_api_key = OpenAiAPIKey.objects.first()
            if openai_api_key:
                openai_api_key.key = key_openai
                openai_api_key.save()
            else:
                OpenAiAPIKey.objects.create(key=key_openai)

        if key_netlas:
            netlas_api_key = NetlasAPIKey.objects.first()
            if netlas_api_key:
                netlas_api_key.key = key_netlas
                netlas_api_key.save()
            else:
                NetlasAPIKey.objects.create(key=key_netlas)

    context = {}
    context["error"] = error

    # Get first available project
    project = get_user_projects(request.user).first()

    context["openai_key"] = OpenAiAPIKey.objects.first()
    context["netlas_key"] = NetlasAPIKey.objects.first()

    # then redirect to the dashboard
    if project:
        slug = project.slug
        return HttpResponseRedirect(reverse("dashboardIndex", kwargs={"slug": slug}))

    # else redirect to the onboarding
    return render(request, "dashboard/onboarding.html", context)


def list_projects(request):
    projects = get_user_projects(request.user)
    return render(request, "dashboard/projects.html", {"projects": projects})


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def edit_project(request, slug):
    project = get_object_or_404(Project, slug=slug)
    if not project.is_user_authorized(request.user):
        messages.error(request, "You don't have permission to edit this project.")
        return redirect("list_projects")

    User = get_user_model()  # noqa: N806
    all_users = User.objects.all()

    if request.method == "POST":
        form = ProjectForm(request.POST, instance=project)
        if form.is_valid():
            # Generate new slug from the project name
            new_slug = slugify(form.cleaned_data["name"])

            # Check if the new slug already exists (excluding the current project)
            if Project.objects.exclude(id=project.id).filter(slug=new_slug).exists():
                form.add_error("name", "A project with a similar name already exists. Please choose a different name.")
            else:
                # Save the form without committing to the database
                updated_project = form.save(commit=False)
                # Set the new slug
                updated_project.slug = new_slug
                # Now save to the database
                updated_project.save()
                # If your form has many-to-many fields, you need to call this
                form.save_m2m()

                messages.success(request, "Project updated successfully.")
                return redirect("list_projects")
    else:
        form = ProjectForm(instance=project)

    return render(request, "dashboard/edit_project.html", {"form": form, "edit_project": project, "users": all_users})


def set_current_project(request, slug):
    if request.method == "GET":
        project = get_object_or_404(Project, slug=slug)
        response = HttpResponseRedirect(reverse("dashboardIndex", kwargs={"slug": slug}))
        response.set_cookie(
            "currentProjectId", project.id, path="/", samesite="Strict", httponly=True, secure=request.is_secure()
        )
        messages.success(request, f"Project {project.name} set as current project.")
        return response
    return HttpResponseBadRequest("Invalid request method. Only GET is allowed.", status=400)


def api_key_management(request):
    """
    Display user's API keys management page.

    Shows list of user's API keys with creation date, last used, and status.
    Allows creation, activation/deactivation, and deletion of API keys.
    """
    user_api_keys = UserAPIKey.objects.filter(user=request.user).order_by("-created_at")
    context = {"api_keys": user_api_keys, "page_title": "API Keys Management"}

    # Check if there's a newly created API key to show
    new_api_key = request.session.pop("new_api_key", None)
    if new_api_key:
        context["new_api_key"] = new_api_key

    return render(request, "dashboard/api_keys.html", context)


def create_api_key(request):
    """
    Create a new API key for the current user.

    Validates the API key name and creates a new UserAPIKey instance.
    Returns the generated key only once for security.
    """
    if request.method == "POST":
        name = request.POST.get("name", "").strip()
        if name:
            # Check if user already has an API key with this name
            if UserAPIKey.objects.filter(user=request.user, name=name).exists():
                messages.error(request, f'API Key with name "{name}" already exists. Please choose a different name.')
            else:
                api_key, key = UserAPIKey.objects.create_key(name=name, user=request.user)
                # Store the new key info in session to display in modal
                request.session["new_api_key"] = {"name": name, "key": key}
                messages.success(request, f'API Key "{name}" created successfully!')
        else:
            messages.error(request, "API Key name is required.")

    return redirect("api_keys")


def delete_api_key(request, key_id):
    """
    Delete an API key belonging to the current user.

    Args:
        key_id (str): Primary key of the API key to delete
    """
    if request.method == "POST":
        try:
            api_key = get_object_or_404(UserAPIKey, pk=key_id, user=request.user)
            key_name = api_key.name
            api_key.delete()
            messages.success(request, f'API Key "{key_name}" deleted successfully.')
        except Exception:
            messages.error(request, "API Key not found or you do not have permission to delete it.")

    return redirect("api_keys")


def toggle_api_key(request, key_id):
    """
    Toggle the active status of an API key.

    Args:
        key_id (str): Primary key of the API key to toggle
    """
    if request.method == "POST":
        try:
            api_key = get_object_or_404(UserAPIKey, pk=key_id, user=request.user)
            api_key.is_active = not api_key.is_active
            api_key.save(update_fields=["is_active"])

            status_text = "activated" if api_key.is_active else "deactivated"
            messages.success(request, f'API Key "{api_key.name}" {status_text} successfully.')
        except Exception:
            messages.error(request, "API Key not found or you do not have permission to modify it.")

    return redirect("api_keys")


# ==============================================================================
# BACKUP SOURCE CODE FEATURE
# ==============================================================================

BACKUP_DIR = "/home/rengine/rengine/backups"
BACKUP_MAX_FILES = 10  # Maksimal 10 file backup disimpan
BACKUP_EXCLUDE_PATTERNS = [
    "__pycache__", "*.pyc", "*.pyo", ".git", "node_modules",
    "staticfiles", "backups", "*.log", ".env", "secrets",
    "celery.log", "celery_beat.log", "errors.log",
]

# Backup progress tracking - Redis-backed untuk multi-worker support
import redis as _redis_module
_backup_lock = threading.Lock()

def _get_redis():
    """Get Redis connection untuk progress tracking."""
    try:
        r = _redis_module.Redis(host='redis', port=6379, db=2, socket_connect_timeout=2)
        r.ping()
        return r
    except Exception:
        return None

def _set_progress(backup_id, data):
    r = _get_redis()
    if r:
        r.setex(f"backup_progress:{backup_id}", 3600, json.dumps(data))
    else:
        # Fallback in-memory
        with _backup_lock:
            _backup_progress_mem[backup_id] = data

def _get_progress(backup_id):
    r = _get_redis()
    if r:
        val = r.get(f"backup_progress:{backup_id}")
        if val:
            return json.loads(val)
    # Fallback in-memory
    return _backup_progress_mem.get(backup_id, {"status": "not_found", "progress": 0, "message": "Backup tidak ditemukan"})

_backup_progress_mem = {}


def _get_backup_dir():
    """Pastikan backup directory ada."""
    os.makedirs(BACKUP_DIR, exist_ok=True)
    return BACKUP_DIR


def _list_backups():
    """Daftar semua file backup, diurutkan dari terbaru."""
    backup_dir = _get_backup_dir()
    backups = []
    for fname in os.listdir(backup_dir):
        if fname.endswith(".tar.gz") and fname.startswith("rengine_backup_"):
            fpath = os.path.join(backup_dir, fname)
            stat = os.stat(fpath)
            backups.append({
                "filename": fname,
                "size": stat.st_size,
                "size_human": _human_size(stat.st_size),
                "created": stat.st_mtime,
            })
    backups.sort(key=lambda x: x["created"], reverse=True)
    return backups


def _human_size(size_bytes):
    """Convert bytes ke human-readable."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} TB"


def _safe_filename(filename):
    """Validasi filename backup agar aman (cegah path traversal)."""
    filename = os.path.basename(filename)
    if not re.match(r'^rengine_backup_[\w\-]+\.tar\.gz$', filename):
        return None
    return filename


def _do_create_backup(backup_id, source_dir, output_path):
    """Jalankan proses backup di background thread."""
    try:
        _set_progress(backup_id, {"status": "running", "progress": 0, "message": "Memulai backup..."})

        # Hitung total file
        total_files = 0
        for root, dirs, files in os.walk(source_dir):
            # Skip excluded dirs
            dirs[:] = [d for d in dirs if d not in BACKUP_EXCLUDE_PATTERNS
                       and not d.startswith('.') and d != 'backups']
            total_files += len(files)

        processed = 0
        with tarfile.open(output_path, "w:gz", compresslevel=6) as tar:
            for root, dirs, files in os.walk(source_dir):
                # Exclude dirs in-place
                dirs[:] = [
                    d for d in dirs
                    if d not in BACKUP_EXCLUDE_PATTERNS
                    and not d.startswith('.')
                    and d != 'backups'
                    and d != 'staticfiles'
                    and d != '__pycache__'
                ]
                for fname in files:
                    # Skip excluded file patterns
                    if any(fname.endswith(ext.lstrip('*')) for ext in ['.pyc', '.pyo', '.log']):
                        continue
                    if fname in ['.env']:
                        continue
                    fpath = os.path.join(root, fname)
                    arcname = os.path.relpath(fpath, os.path.dirname(source_dir))
                    try:
                        tar.add(fpath, arcname=arcname)
                    except (OSError, PermissionError):
                        pass
                    processed += 1
                    if total_files > 0:
                        pct = int((processed / total_files) * 100)
                        if processed % 20 == 0:  # Update setiap 20 file
                            _set_progress(backup_id, {"status": "running", "progress": pct, "message": f"Memproses file ({processed}/{total_files})..."})

        _set_progress(backup_id, {
            "status": "done",
            "progress": 100,
            "message": "Backup selesai!",
            "filename": os.path.basename(output_path),
        })

        # Hapus backup lama jika melebihi batas
        existing = sorted(
            [f for f in os.listdir(BACKUP_DIR) if f.endswith(".tar.gz")],
            key=lambda f: os.path.getmtime(os.path.join(BACKUP_DIR, f))
        )
        while len(existing) > BACKUP_MAX_FILES:
            old = os.path.join(BACKUP_DIR, existing.pop(0))
            try:
                os.remove(old)
            except OSError:
                pass

    except Exception as e:
        _set_progress(backup_id, {
            "status": "error",
            "progress": 0,
            "message": f"Error: {str(e)}",
        })


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def backup_source_code(request):
    """Mulai proses backup source code secara async."""
    if request.method != "POST":
        return JsonResponse({"status": False, "error": "Method not allowed"}, status=405)

    backup_id = f"backup_{int(time.time())}"
    timestamp = django_now().strftime("%Y%m%d_%H%M%S")
    backup_filename = f"rengine_backup_{timestamp}.tar.gz"
    source_dir = "/home/rengine/rengine"
    output_path = os.path.join(_get_backup_dir(), backup_filename)

    # Inisialisasi progress
    with _backup_lock:
        _set_progress(backup_id, {"status": "starting", "progress": 0, "message": "Menginisialisasi..."})

    # Jalankan backup di background thread
    t = threading.Thread(
        target=_do_create_backup,
        args=(backup_id, source_dir, output_path),
        daemon=True
    )
    t.start()

    return JsonResponse({"status": True, "backup_id": backup_id, "filename": backup_filename})


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def backup_progress(request, backup_id):
    """Cek progress backup (SSE / polling)."""
    with _backup_lock:
        data = _get_progress(backup_id)
    return JsonResponse(data)


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def backup_list(request):
    """Return daftar backup sebagai JSON."""
    backups = _list_backups()
    return JsonResponse({"status": True, "backups": backups})


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def backup_download(request, filename):
    """Download file backup."""
    safe_name = _safe_filename(filename)
    if not safe_name:
        raise Http404("File tidak ditemukan")

    fpath = os.path.join(_get_backup_dir(), safe_name)
    if not os.path.isfile(fpath):
        raise Http404("File tidak ditemukan")

    response = FileResponse(
        open(fpath, "rb"),
        content_type="application/gzip",
        as_attachment=True,
        filename=safe_name,
    )
    return response


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def backup_delete(request, filename):
    """Hapus file backup."""
    if request.method != "POST":
        return JsonResponse({"status": False, "error": "Method not allowed"}, status=405)

    safe_name = _safe_filename(filename)
    if not safe_name:
        return JsonResponse({"status": False, "error": "Nama file tidak valid"})

    fpath = os.path.join(_get_backup_dir(), safe_name)
    if not os.path.isfile(fpath):
        return JsonResponse({"status": False, "error": "File tidak ditemukan"})

    try:
        os.remove(fpath)
        return JsonResponse({"status": True, "message": f"Backup {safe_name} berhasil dihapus"})
    except OSError as e:
        return JsonResponse({"status": False, "error": str(e)})


# ==============================================================================
# GOOGLE DRIVE BACKUP FEATURE
# ==============================================================================
# Credential disimpan di Redis key "gdrive_credentials" (JSON service-account)
# atau bisa pakai OAuth2 via flow.  Folder ID target: 0AMzZ2vjfVdc1Uk9PVA
# ==============================================================================

GDRIVE_FOLDER_ID_DEFAULT = "0AMzZ2vjfVdc1Uk9PVA"
GDRIVE_CRED_REDIS_KEY = "gdrive_service_account_json"
GDRIVE_TOKEN_REDIS_KEY = "gdrive_oauth_token_json"
GDRIVE_UPLOAD_PROGRESS_KEY = "gdrive_upload_progress:{upload_id}"

# ------------ helpers ---------------------------------------------------------

def _gdrive_get_service_account_json():
    """Ambil service-account JSON dari Redis."""
    r = _get_redis()
    if r:
        val = r.get(GDRIVE_CRED_REDIS_KEY)
        if val:
            return json.loads(val)
    return None


def _gdrive_save_service_account_json(data: dict):
    r = _get_redis()
    if r:
        r.set(GDRIVE_CRED_REDIS_KEY, json.dumps(data))
        return True
    return False


def _gdrive_get_oauth_token():
    r = _get_redis()
    if r:
        val = r.get(GDRIVE_TOKEN_REDIS_KEY)
        if val:
            return json.loads(val)
    return None


def _gdrive_save_oauth_token(token_data: dict):
    r = _get_redis()
    if r:
        r.set(GDRIVE_TOKEN_REDIS_KEY, json.dumps(token_data))
        return True
    return False


def _gdrive_build_service():
    """
    Build Google Drive API service.
    Priority: Service Account JSON → OAuth2 token
    """
    try:
        from google.oauth2 import service_account
        from google.oauth2.credentials import Credentials
        from googleapiclient.discovery import build

        sa_json = _gdrive_get_service_account_json()
        if sa_json:
            creds = service_account.Credentials.from_service_account_info(
                sa_json,
                scopes=["https://www.googleapis.com/auth/drive"],
            )
            return build("drive", "v3", credentials=creds, cache_discovery=False)

        token_data = _gdrive_get_oauth_token()
        if token_data:
            creds = Credentials.from_authorized_user_info(token_data)
            return build("drive", "v3", credentials=creds, cache_discovery=False)

        return None
    except Exception as e:
        logger.error(f"[GDrive] build_service error: {e}")
        return None


def _set_upload_progress(upload_id, data):
    r = _get_redis()
    key = GDRIVE_UPLOAD_PROGRESS_KEY.format(upload_id=upload_id)
    if r:
        r.setex(key, 3600, json.dumps(data))
    else:
        with _backup_lock:
            _backup_progress_mem[key] = data


def _get_upload_progress(upload_id):
    r = _get_redis()
    key = GDRIVE_UPLOAD_PROGRESS_KEY.format(upload_id=upload_id)
    if r:
        val = r.get(key)
        if val:
            return json.loads(val)
    return _backup_progress_mem.get(key, {"status": "not_found", "progress": 0, "message": "Upload tidak ditemukan"})


def _do_gdrive_upload(upload_id, local_path, folder_id):
    """Upload file backup ke Google Drive di background thread."""
    try:
        from googleapiclient.http import MediaFileUpload

        _set_upload_progress(upload_id, {"status": "running", "progress": 5, "message": "Menghubungkan ke Google Drive..."})

        service = _gdrive_build_service()
        if not service:
            _set_upload_progress(upload_id, {"status": "error", "progress": 0, "message": "Google Drive tidak terkonfigurasi. Silakan upload credentials terlebih dahulu."})
            return

        filename = os.path.basename(local_path)
        file_size = os.path.getsize(local_path)

        _set_upload_progress(upload_id, {"status": "running", "progress": 10, "message": f"Mengupload {filename} ({_human_size(file_size)})..."})

        # Check if file already exists → delete old
        try:
            existing = service.files().list(
                q=f"name='{filename}' and '{folder_id}' in parents and trashed=false",
                fields="files(id,name)",
            ).execute()
            for f in existing.get("files", []):
                service.files().delete(fileId=f["id"]).execute()
        except Exception:
            pass

        file_metadata = {
            "name": filename,
            "parents": [folder_id],
        }
        media = MediaFileUpload(
            local_path,
            mimetype="application/gzip",
            resumable=True,
            chunksize=4 * 1024 * 1024,  # 4 MB chunks
        )

        request_upload = service.files().create(
            body=file_metadata,
            media_body=media,
            fields="id,name,webViewLink,size",
        )

        response = None
        while response is None:
            status, response = request_upload.next_chunk()
            if status:
                pct = int(status.progress() * 90) + 10  # 10-100%
                _set_upload_progress(upload_id, {
                    "status": "running",
                    "progress": pct,
                    "message": f"Mengupload... {pct}%",
                })

        file_id = response.get("id", "")
        web_link = response.get("webViewLink", f"https://drive.google.com/file/d/{file_id}/view")

        _set_upload_progress(upload_id, {
            "status": "done",
            "progress": 100,
            "message": f"Upload selesai! File tersimpan di Google Drive.",
            "file_id": file_id,
            "web_link": web_link,
            "filename": filename,
        })

    except Exception as e:
        logger.error(f"[GDrive] upload error: {e}")
        _set_upload_progress(upload_id, {
            "status": "error",
            "progress": 0,
            "message": f"Error upload: {str(e)}",
        })


def _gdrive_list_backups(folder_id):
    """Ambil daftar file backup dari folder Google Drive."""
    try:
        service = _gdrive_build_service()
        if not service:
            return []
        result = service.files().list(
            q=f"'{folder_id}' in parents and trashed=false and name contains 'rengine_backup_'",
            fields="files(id,name,size,createdTime,webViewLink,modifiedTime)",
            orderBy="createdTime desc",
            pageSize=50,
        ).execute()
        files = result.get("files", [])
        out = []
        for f in files:
            sz = int(f.get("size", 0))
            out.append({
                "id": f["id"],
                "filename": f["name"],
                "size": sz,
                "size_human": _human_size(sz),
                "created_time": f.get("createdTime", ""),
                "modified_time": f.get("modifiedTime", ""),
                "web_link": f.get("webViewLink", f"https://drive.google.com/file/d/{f['id']}/view"),
            })
        return out
    except Exception as e:
        logger.error(f"[GDrive] list_backups error: {e}")
        return []


# ------------ views -----------------------------------------------------------

@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def gdrive_status(request):
    """Cek status koneksi Google Drive dan daftar file backup."""
    sa = _gdrive_get_service_account_json()
    oauth = _gdrive_get_oauth_token()

    auth_method = None
    service_account_email = None
    if sa:
        auth_method = "service_account"
        service_account_email = sa.get("client_email", "")
    elif oauth:
        auth_method = "oauth2"
    else:
        return JsonResponse({"status": False, "connected": False, "message": "Belum terkonfigurasi"})

    # Test connection
    try:
        service = _gdrive_build_service()
        if not service:
            return JsonResponse({"status": False, "connected": False, "message": "Gagal membuat koneksi"})

        folder_id = request.GET.get("folder_id", GDRIVE_FOLDER_ID_DEFAULT)

        # Try to get folder info
        try:
            folder_info = service.files().get(fileId=folder_id, fields="id,name").execute()
            folder_name = folder_info.get("name", folder_id)
        except Exception:
            folder_name = folder_id

        # List backup files
        backups = _gdrive_list_backups(folder_id)

        return JsonResponse({
            "status": True,
            "connected": True,
            "auth_method": auth_method,
            "service_account_email": service_account_email,
            "folder_id": folder_id,
            "folder_name": folder_name,
            "backups": backups,
            "backup_count": len(backups),
        })
    except Exception as e:
        return JsonResponse({"status": False, "connected": False, "message": str(e)})


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def gdrive_upload_backup(request):
    """Upload file backup lokal ke Google Drive."""
    if request.method != "POST":
        return JsonResponse({"status": False, "error": "Method not allowed"}, status=405)

    data = json.loads(request.body) if request.content_type == "application/json" else request.POST
    filename = data.get("filename", "")
    folder_id = data.get("folder_id", GDRIVE_FOLDER_ID_DEFAULT)

    safe_name = _safe_filename(filename)
    if not safe_name:
        return JsonResponse({"status": False, "error": "Nama file tidak valid"})

    fpath = os.path.join(_get_backup_dir(), safe_name)
    if not os.path.isfile(fpath):
        return JsonResponse({"status": False, "error": "File backup tidak ditemukan"})

    # Cek apakah sudah ada credentials
    if not _gdrive_get_service_account_json() and not _gdrive_get_oauth_token():
        return JsonResponse({"status": False, "error": "Google Drive belum terkonfigurasi. Upload Service Account JSON terlebih dahulu."})

    upload_id = f"gdrive_{int(time.time())}"
    _set_upload_progress(upload_id, {"status": "starting", "progress": 0, "message": "Memulai upload..."})

    t = threading.Thread(
        target=_do_gdrive_upload,
        args=(upload_id, fpath, folder_id),
        daemon=True,
    )
    t.start()

    return JsonResponse({"status": True, "upload_id": upload_id, "filename": safe_name})


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def gdrive_upload_progress(request, upload_id):
    """Cek progress upload ke Google Drive."""
    data = _get_upload_progress(upload_id)
    return JsonResponse(data)


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def gdrive_save_credentials(request):
    """
    Simpan Service Account JSON credentials ke Redis.
    Body: { "credentials_json": "<raw JSON string>" }
    """
    if request.method != "POST":
        return JsonResponse({"status": False, "error": "Method not allowed"}, status=405)

    try:
        body = json.loads(request.body)
    except (json.JSONDecodeError, ValueError):
        return JsonResponse({"status": False, "error": "Body harus berupa JSON"})

    cred_raw = body.get("credentials_json", "")
    if not cred_raw:
        return JsonResponse({"status": False, "error": "credentials_json wajib diisi"})

    try:
        cred_data = json.loads(cred_raw) if isinstance(cred_raw, str) else cred_raw
    except (json.JSONDecodeError, ValueError):
        return JsonResponse({"status": False, "error": "credentials_json bukan JSON yang valid"})

    # Validasi minimal field service account
    required_fields = ["type", "project_id", "private_key", "client_email"]
    missing = [f for f in required_fields if f not in cred_data]
    if missing:
        return JsonResponse({"status": False, "error": f"Field wajib tidak ada: {', '.join(missing)}"})

    if cred_data.get("type") != "service_account":
        return JsonResponse({"status": False, "error": "Hanya Service Account JSON yang didukung"})

    if not _gdrive_save_service_account_json(cred_data):
        return JsonResponse({"status": False, "error": "Gagal menyimpan ke Redis"})

    # Test connection
    try:
        service = _gdrive_build_service()
        if service:
            about = service.files().list(pageSize=1, fields="files(id)").execute()
            return JsonResponse({
                "status": True,
                "message": "Credentials berhasil disimpan dan koneksi Google Drive berhasil!",
                "service_account_email": cred_data.get("client_email"),
            })
        else:
            return JsonResponse({"status": False, "error": "Credentials disimpan tapi gagal konek ke Google Drive"})
    except Exception as e:
        return JsonResponse({"status": False, "error": f"Credentials disimpan tapi koneksi gagal: {str(e)}"})


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def gdrive_delete_credentials(request):
    """Hapus credentials Google Drive dari Redis."""
    if request.method != "POST":
        return JsonResponse({"status": False, "error": "Method not allowed"}, status=405)

    r = _get_redis()
    if r:
        r.delete(GDRIVE_CRED_REDIS_KEY)
        r.delete(GDRIVE_TOKEN_REDIS_KEY)
    return JsonResponse({"status": True, "message": "Credentials Google Drive berhasil dihapus"})


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def gdrive_delete_remote(request, file_id):
    """Hapus file backup dari Google Drive."""
    if request.method != "POST":
        return JsonResponse({"status": False, "error": "Method not allowed"}, status=405)

    try:
        service = _gdrive_build_service()
        if not service:
            return JsonResponse({"status": False, "error": "Google Drive tidak terkonfigurasi"})
        service.files().delete(fileId=file_id).execute()
        return JsonResponse({"status": True, "message": "File berhasil dihapus dari Google Drive"})
    except Exception as e:
        return JsonResponse({"status": False, "error": str(e)})
