#!/usr/bin/env bash
#
# install-desktop.sh
# Memasang lingkungan desktop XFCE + LightDM pada server Ubuntu headless,
# lalu mengatur AUTOLOGIN agar selalu ada sesi desktop aktif yang bisa
# di-capture RustDesk (unattended access).
#
# Pakai:
#   sudo bash install-desktop.sh                      # buat user 'remote' + autologin
#   sudo DESKTOP_USER=budi bash install-desktop.sh    # pakai/gunakan user tertentu
#   sudo AUTOLOGIN=no bash install-desktop.sh          # tanpa autologin (lebih aman)
#
# Catatan: autologin memudahkan RustDesk (sesi selalu hidup) tapi berarti
# siapa pun dengan akses konsol fisik langsung masuk sesi. Di VPS tanpa
# konsol fisik ini umumnya aman; di mesin fisik pertimbangkan AUTOLOGIN=no.
#
set -euo pipefail

log()  { echo -e "\033[1;32m[+]\033[0m $*"; }
warn() { echo -e "\033[1;33m[!]\033[0m $*"; }
err()  { echo -e "\033[1;31m[x]\033[0m $*" >&2; }

DESKTOP_USER="${DESKTOP_USER:-remote}"
AUTOLOGIN="${AUTOLOGIN:-yes}"

### 0. Root ---------------------------------------------------------
if [[ "$(id -u)" -ne 0 ]]; then
  err "Jalankan sebagai root (pakai sudo)."
  exit 1
fi

### 1. Install XFCE + display manager -------------------------------
log "Menginstall XFCE + LightDM (butuh beberapa menit)..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
# --no-install-recommends menekan bloat; tambahkan goodies bila mau lengkap
apt-get install -y \
  xfce4 xfce4-goodies \
  lightdm lightdm-gtk-greeter \
  xorg dbus-x11 x11-xserver-utils

### 2. Pastikan LightDM jadi display manager default ----------------
log "Menetapkan LightDM sebagai display manager..."
echo "/usr/sbin/lightdm" > /etc/X11/default-display-manager
# jawab otomatis debconf jika ada dialog dm
echo "lightdm shared/default-x-display-manager select lightdm" | debconf-set-selections || true
dpkg-reconfigure -f noninteractive lightdm || true

### 3. Siapkan user desktop -----------------------------------------
if ! id "$DESKTOP_USER" >/dev/null 2>&1; then
  log "Membuat user '$DESKTOP_USER'..."
  adduser --disabled-password --gecos "" "$DESKTOP_USER"
  warn "User '$DESKTOP_USER' dibuat tanpa password. Set password login OS bila perlu:"
  warn "  sudo passwd $DESKTOP_USER"
else
  log "User '$DESKTOP_USER' sudah ada, dipakai."
fi

# set sesi default user ke XFCE
sudo -u "$DESKTOP_USER" bash -c 'echo "xfce4-session" > ~/.xsession' || true

### 4. Konfigurasi autologin (opsional) -----------------------------
LIGHTDM_CONF_DIR="/etc/lightdm/lightdm.conf.d"
mkdir -p "$LIGHTDM_CONF_DIR"
if [[ "$AUTOLOGIN" == "yes" ]]; then
  log "Mengaktifkan autologin untuk '$DESKTOP_USER'..."
  # grup autologin diperlukan agar autologin tanpa password diterima
  groupadd -f autologin
  gpasswd -a "$DESKTOP_USER" autologin >/dev/null || true
  cat > "${LIGHTDM_CONF_DIR}/50-autologin.conf" <<EOF
[Seat:*]
autologin-user=${DESKTOP_USER}
autologin-user-timeout=0
autologin-session=xfce
user-session=xfce
EOF
else
  log "Autologin dilewati (AUTOLOGIN=no). LightDM akan menampilkan layar login."
  rm -f "${LIGHTDM_CONF_DIR}/50-autologin.conf" 2>/dev/null || true
fi

### 5. Set target grafis & mulai LightDM ----------------------------
log "Mengatur boot ke mode grafis..."
systemctl set-default graphical.target
systemctl enable lightdm >/dev/null 2>&1 || true
systemctl restart lightdm || warn "Gagal restart lightdm sekarang; akan aktif setelah reboot."

### 6. Ringkasan ----------------------------------------------------
echo
log "=========== DESKTOP SIAP ==========="
echo "  Desktop      : XFCE 4.18"
echo "  Display mgr  : LightDM"
echo "  User sesi    : ${DESKTOP_USER}"
echo "  Autologin    : ${AUTOLOGIN}"
echo "  Default boot : $(systemctl get-default 2>/dev/null)"
echo "===================================="
echo
echo "Langkah berikut:"
echo "  1) Reboot disarankan:  sudo reboot"
echo "  2) Setelah boot, sesi XFCE aktif & bisa di-capture RustDesk."
echo "  3) Jalankan konfigurasi unattended RustDesk bila belum:"
echo "       sudo bash rustdesk-unattended.sh"
if [[ "$AUTOLOGIN" == "yes" ]]; then
  echo
  warn "Autologin AKTIF: sesi desktop selalu terbuka tanpa password OS."
  warn "Pastikan RustDesk pakai permanent password yang kuat sebagai lapis akses."
fi

