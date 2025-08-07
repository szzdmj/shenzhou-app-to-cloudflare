<?php
echo "✅ Hello from FrankenPHP via Caddy!";
require('common.inc.php');
require(APPDIR.'/config.inc.php');
require(APPDIR.'/include/func.inc.php');
require(APPDIR.'/include/http.inc.php');
require(APPDIR.'/include/coding.inc.php');
require(APPDIR.'/include/pwa.inc.php');

// ================================================================================================
// 初始化
// ================================================================================================

if($_SERVER['REQUEST_METHOD'] == 'OPTIONS'){
	on_response_options();
}

//获取网站根路径
$app_path = str_replace('/index.php', '/', ($_SERVER['SCRIPT_NAME']?$_SERVER['SCRIPT_NAME']:$_SERVER['PHP_SELF']));

//检查是否有必需的设置项
if(empty($config) || empty($address)){
	exit('没找到设置');
}

//建立必需的目录
if(!is_dir(DATADIR)) mkdirs(DATADIR) or die('无法建立data目录，请检查权限！');
if(!is_dir(TEMPDIR)) mkdirs(TEMPDIR) or die('无法建立temp目录，请检查权限！');

//初始化设置
init_config();

//避免调试时xdebug附加参数的影响
if(isset($_GET['XDEBUG_SESSION_START'])){
    unset($_GET['XDEBUG_SESSION_START'], $_GET['KEY']);
    $_SERVER['REQUEST_URI'] = preg_replace('#([\?&])XDEBUG_SESSION_START=[\w\-]+(&KEY=\d+)?$#', '', $_SERVER['REQUEST_URI']);
}

//移除在微信里浏览时自动添加的一大堆后缀
if( preg_match('#(\?|&)nsukey=[\w\%\-]{50,}$#', $_SERVER['REQUEST_URI'], $match)){
	unset($_GET['nsukey']);
	$_SERVER['REQUEST_URI'] = substr($_SERVER['REQUEST_URI'],0,-strlen($match[0]));
}

//检查网址里是否有危险字符
if(preg_match('#%0[0ad]#i', $_SERVER['REQUEST_URI'])){
	show_error(404);
}

//初始化其他几个变量
$currentUrl = Url::getCurrentUrl();
$urlCoding = new UrlCoding($currentUrl);
$remoteReferer = $urlCoding->getRefererString();
$currentReferer = isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '';
set_error_handler("myErrorHandler");
$error_messages = null;
$ctype = null;
$ext = fileext($_SERVER['REQUEST_URI']);

//镜像站点功能
if(!empty($config['mirror_site'])){
	require(APPDIR."/include/mirror.inc.php");
}

//载入自定义插件
if($config['plugin'] && file_exists(APPDIR."/plugin/{$config['plugin']}.php")){
	require(APPDIR."/plugin/{$config['plugin']}.php");
}

// ================================================================================================
// 动作
// ================================================================================================

$requestUri = $_SERVER['REQUEST_URI'];
$isIndexPhp = !isset($_GET['__nonematch__']);

//请求由“智能跳转网站程序”提交
if($_SERVER['REQUEST_METHOD']=='HEAD' && Http::isSpider()=='jump'){
    exit;
}

//被block的链接
if (strpos($requestUri, "/?{$config['block_var_name']}=")===0 ||
    strpos($requestUri, '/blank/')===0 ||
    strpos($requestUri, '//blank/')===0
) {
    if(!isset($_SERVER['HTTP_ACCEPT']) || substr($_SERVER['HTTP_ACCEPT'],0,5)=='text/'){
        //
    }else{
        $s = preg_replace('#[\s\,].+#', '', $_SERVER['HTTP_ACCEPT']);
        if($s && preg_match('#^\w+/\w+$#',$s)){
            header('Content-Type: ' . $s);
        }
    }
    header('HTTP/1.1 200 OK');
    header('Access-Control-Allow-Origin: *');
    header('Cache-Control: public, max-age=31536000');
    header('Expires: '.gmtDate("+1 year"));
    header('Content-Length: 0');
    exit;
}

//禁止访问CNAME_DOMAIN
if(CNAME_DOMAIN && $currentUrl->root==CNAME_DOMAIN){
    show_error(404);
}

//提取原始网址里的$_GET
if(!$isIndexPhp && ($arr=explode('?',$requestUri,2)) && !empty($arr[1])){
    parse_str($arr[1], $_GET);
}

//禁止直接访问favicon.ico
if(strpos($requestUri, '/favicon.ico')===0){
    //使用此页和此头识别程序用于有效性检测
    header('X-Powered-By: PHP/7.6.7');
    show_error(404);
    exit;
}

//输出robots.txt，并添加响应头
if(strpos($requestUri, '/robots.txt')===0){
	//使用此页和此头识别程序用于有效性检测
	header('Content-Type: text/plain');
	header('Cache-Control: public, max-age=31536000');
	header('Expires: '.gmtDate("+1 year"));
	header('X-Powered-By: PHP/7.6.7');
	echo "User-agent: *\r\nDisallow: /\r\n";
	exit;
}

//判断是否从ATS直接回源的
if(!empty($config['is_behind_ats']) && $requestUri=='/TEST_STATIC_FOR_ATS.png'){
    header('Content-Type: text/plain; charset=GBK');
    echo '支持从ATS直接回源';
    exit;
}

//可能是images接口
if(in_array(substr($requestUri,0,8),['/images/','/assets/'])){
    call_images_api($currentUrl, $requestUri);
}

//禁止js bot访问，并对此ip持续阻止10分钟
$forbid_js_bot = false;
$cacheName = 'js_bot_checker:' . get_ip();
$kv = KeyValue();
if($kv->exists($cacheName, 600)){
    $forbid_js_bot = true;
}else{
    $cookieName = HtmlCoding::getFuncName() . 'bt';
    if(isset($_COOKIE[$cookieName]) && abs(time()-intval($_COOKIE[$cookieName]))<600){
        $forbid_js_bot = true;
        $kv->set($cacheName, 1, 600);
    }
}
if($forbid_js_bot){
    show_error(404, '', false, true);
}

//crossdomain.xml
if($requestUri=='/crossdomain.xml'){
	header('Content-Type: application/xml');
	header('Cache-Control: public, max-age=31536000');
	header('Expires: '.gmtDate("+1 year"));
	echo '<?xml version="1.0"?><cross-domain-policy><allow-access-from domain="*" /></cross-domain-policy>';
	exit;
}

//在jwplayer.js里调用，根据是否为中国大陆用户调用回调函数
if($isIndexPhp && isset($_GET['cn']) && preg_match('#^jsonp\d+$#',$_GET['cn'])){
    header('Content-Type: text/javascript');
    $x = in_array(get_user_country(false),array('CN','LOCAL'))?'1':'0';
    echo "{$_GET['cn']}({$x});";
    exit;
}

//访问/?home时，如果改变了homepage_style，就需要转向到第一个网址
if($isIndexPhp && isset($_GET['home']) && empty($_GET['home']) && !empty($config['homepage_style'])){
    forbid_ip_server();
    check_url_hash($requestUri);
	$arr = explode('|', reset($address));
    $url = end($arr);
    $url = $urlCoding->encodeUrl($url, null, null, true);
    show_404_redirect($url, false);
}

//首页内容样式(显示为空白页、错误页或其它特定页)
if(!empty($config['homepage_style']) && empty($config['mirror_site']) && preg_match('#^/(index\.php)?(\?|\?\w+=?)?$#',$_SERVER['REQUEST_URI'])){
    $appUid = get_app_uid();
    if($appUid){
        header("X-App-Uid: {$appUid}");
    }

    if($remoteReferer && preg_match('#^https?://[\w\-\.:]+/#', $remoteReferer, $match)){
        //从来源网址里提取首页
        $remoteUrl = Url::create($match[0]);
    }else{
        //首页内容类型
        $style=$config['homepage_style'];
        if($style[0]=='/'){
            if(preg_match('#^([^?]+?\.html?)#', $style, $match) && file_exists(APPDIR . $match[1])){
                $_SERVER['REQUEST_URI'] = $style;
                readfile(APPDIR . $match[1]);
            }else{
                show_404_redirect($style,true);
            }
        }else{
            $file=DATADIR."/error/{$style}.txt";
            $content=file_exists($file)?file_get_contents($file):'';
            if(!is_numeric($style)){
                echo $content;
            }else{
                show_error($style, $content);
            }
        }
        exit;
    }
}

//提取参数
$builtInAction = $builtIn = $builtInExt = '';
$builtInName = $config['built_in_name'];
if($isIndexPhp && !empty($_GET[$builtInName])){
	$builtIn = $_GET[$builtInName];
}elseif(!$isIndexPhp && strpos($requestUri,"/{$builtInName}")!==false &&
    preg_match('#^(?:/'.$builtInName.'_|/images/'.$builtInName.'/)([\w-]+)(\.\w{2,4})?(\?|$)#', $requestUri, $match))
{
    $builtIn = $match[1];
    $builtInExt = $match[2];
}
if($builtIn){
    $decryptedBuiltIn = decrypt_builtin($builtIn);
    if($decryptedBuiltIn && $decryptedBuiltIn!=$builtIn){
        $builtInAction = $decryptedBuiltIn;
        if(preg_match('#^_(ytb|ytbl|ytbimg)_([\w\-]+?)(\.\w{2,4})?(\?_=\w*)?$#', $builtInAction, $match)){
    	    $builtInAction = $match[1];
    	    $youtubeId = $match[2];
    	    if(!empty($match[3])) $builtInExt = $match[3];
        }
    }
}
if($builtInAction && substr($builtInAction,-strlen(APP_VER)-1)=='_'.APP_VER){
    $builtInAction = substr($builtInAction,0,-strlen(APP_VER)-1);
}
if(empty($builtInAction)){
    //youtube伪静态形式网址
    //存在校验参数的是新形式，【建议使用】
    //不存在校验参数的是旧形式，因为跟域名不相关，可能会被当作特征，不建议使用
    $urlHash = null;
    if(substr($requestUri,0,5)=='/_ytb'){
        if(preg_match('#^/_(ytb|ytbl|ytbimg)/([\w\-]+?)(_[0-9a-f]{8})?\.(rss|mp3|mp4|jpg)(?:\?(?:_=)?(\w*))?$#', $requestUri, $match)){
            $builtInAction = $match[1];
            $youtubeId = $match[2];
			$urlHash = !empty($match[3]) ? substr($match[3],1) : @$match[5];
			if(!check_url_hash("/_{$builtInAction}/{$youtubeId}.{$match[4]}", $urlHash)){
                $urlHash = null;
                $youtubeId .= $match[3];
            }
        }
    //youtube动态形式网址，因为没有扩展名，不能被某些媒体播放器正确识别，所以不建议使用
    }elseif(!empty($_GET) && preg_match('#^/\?_(ytb|ytbt|ytbl|ytbimg)=([\w\-]+)(&|$)#', $requestUri, $match)){
        $builtInAction = $match[1];
        $youtubeId = $match[2];
        if(check_url_hash($requestUri)){
            $urlHash = true;
        }
    }
    //验证
    if($builtInAction && $builtInAction!='ytbt' && $youtubeId && !$urlHash && empty($_SERVER['HTTP_X_FORWARD_S']) && !get_app_uid() && !check_cookie_redirect($requestUri)){
        show_cookie_redirect($requestUri);
    }
}

//是否在其它CDN后
$is_behind_cdn =
	!empty($config['is_behind_cloudflare']) ||
	!empty($config['is_behind_cloudfront']) ||
	!empty($config['is_behind_heroku']) ||
	!empty($config['is_behind_ats']);

/*
if($builtInAction && DEBUGING>0){
    header("Action: {$builtInAction}");
}
*/


$pwa = new PWA();
switch ($builtInAction){
    case 'js': //js解密函数的网址参数和函数名
        show_action_js();
        exit;
    case 'nav': //底部导航条javascript的显示与控制，如果向后台发送的请求头里包含 X-Nav-Visible: 0 就不显示底部导航条
	case 'nav_0':
	case 'nav_1':
        if(!isset($_SERVER['HTTP_X_NAV_VISIBLE'])) show_navigation_js();
        exit;
    case 'tj': //记录统计信息、与数据中心服务器同步、检查是否需清除缓存
    	//如果返回404，可能无法把cookie传递给浏览器，所以这里要返回200响应码
    	header('Cache-Control: no-cache, must-revalidate');
    	header('Pragma: no-cache');
        header('Content-Type: text/html; charset='.APP_CHARSET);

        $cookieName = $config['cookie_counter'];
        $cookieValue = isset($_COOKIE[$cookieName]) ? $_COOKIE[$cookieName] : '';
        if(!$cookieValue){
            //无效的首次访问，或者访客浏览器不支持cookie
            if(DEBUGING) echo '//tj:1';
        }else{
            $cookieKeys = str_split(md5_16(php_uname().$currentUrl->host.$_SERVER['HTTP_USER_AGENT']), 8);
            $clientParamTime = isset($_GET['_']) && preg_match('#^'.$cookieKeys[1].'(\w{6})$#',$_GET['_'],$m) ? base_convert($m[1],36,10) : 0;
            if(TIME-$clientParamTime>3600){
                //如果服务器与客户端的时间差超过1小时，则不计入访问统计
                if(DEBUGING) echo '//tj:2';
            }else{
                //countv
                if(is_numeric($cookieValue)){
                    //回头客，有上次来访时间，每隔1小时更新一次上次访问时间，连续24小时没有更新则会导致此cookie失效，然后再访问就算是新的访客了
                    //这个更新现已放到js里执行了
                    //if(TIME-$cookieValue>3600) setcookie_ex($cookieName, TIME, 86400);
                }elseif(
                    preg_match('#^u'.$cookieKeys[0].'(\w{6})$#',$cookieValue,$m) &&
                    ($clientCookieTime=base_convert($m[1],36,10)) &&
                    $clientParamTime==$clientCookieTime
                ){
                    //认定为有效新访客，添加访问记录，并用cookie记录访问时间(以1小时为单位，以避免由于此cookie导致无法缓存)
                    setcookie_ex($cookieName, intdiv(TIME,3600), 86400);
                    record_counter('visit');
                    //如果是大陆ipv4访客，就记录当前域名为历史域名（会导致此域名的有效性提高）
                    if( (get_user_country(true)==='CN' || (DEBUGING && get_user_country(true)==='LOCAL')) &&
                        !empty($config['sync_server']) &&
                        include_once(APPDIR.'/include/sync.inc.php')
                    ){
                        $sync = new Sync();
                        $result = $sync->recordHistDomain($currentUrl);
                        if(isset($config['sync_disable_upload'])){
                            echo $result;
                        }
                    }
                }else{
                    setcookie_ex($cookieName, '', 86400);
                    //无效的首次访问，或者访客浏览器不支持cookie
                    if(DEBUGING) echo '//tj:3';
                }
            }
        }

        //检查定时任务
        check_cron_jobs($currentUrl);
        exit;
    case 'favicon':
        if(isset($_GET['_']) && $pwa->parseRequest($_GET['_'])){
            //响应pwa接口，_=【uid】【c或n】，c表示请求验证，n表示获取节点（节点网址先用逗号分隔然后加密）
            switch($pwa->action){
                case PWA::PWA_ACTION_NODES:
                    //返回cf和泛域名
                    $nodes = geturl_from_sync_server('&new=1&hist=1&cf=1&https=1&count=10', false, 10);
                    if(!$nodes || substr($nodes,0,5)==='[ERR]'){
                        show_error(404);
                    }else{
                        $pwa->outputFaviconAndNodes($nodes);
                    }
                    break;
                case PWA::PWA_ACTION_CHECK:
                    $pwa->outputAsIcon($pwa->expected);
                    break;
                default:
                    show_error(404);
                    break;
            }
        }elseif(file_exists(APPDIR.'/images/favicon.ico')){
            //输出favicon
            $data = file_get_contents(APPDIR.'/images/favicon.ico');
            header('Cache-Control: public, max-age=604800');
            header('Expires: '.gmtDate("+7 day"));
            header('Content-Type: image/x-icon');
            header('Content-Length: '.strlen($data));
            echo $data;
            exit;
        }else{
            show_error(404);
        }
    case 'ytb': //播放youtube单个视频
        $videourl = '';
        if($youtubeId){
            if(!empty($_SERVER['HTTP_X_FORWARD_S'])){
                $pwa->forward202("/_ytb/{$youtubeId}.mp4");
            }
        	if(!empty($config['is_behind_cloudfront']) && !empty($config['sync_server'])){
        		show_wildcard_redirect("/_ytb/{$youtubeId}.mp4", false, true, true);
        	}
            $videourl = getYoutubeVideoUrl($youtubeId);
        }
        if(!$videourl){
            show_error(404);
        }elseif(get_app_uid()){
            $remoteUrl = Url::create($videourl);
            $_GET[$config['ctype_var_name']] = $ctype = 'media';
        }else{
        	$url = $urlCoding->encodeUrl($videourl,'video',null,true);
        	show_redirect($url);
        }
        break;
    case 'ytbt': //获取youtube单个视频网址
        $videourl = '';
        if($youtubeId){
            if(!empty($_POST['data'])){
                $youtubeData =  urlsafe_base64_decode(str_rot13($_POST['data']));
                $part = get_between($youtubeData, $currentUrl->home.'/h1/', '/videoplayback', false);
                if($part){
                    $home = $urlCoding->decodeParts("/h1/{$part}");
                    if($home){
                        $youtubeData = str_replace("{$currentUrl->home}/h1/{$part}/videoplayback", "{$home}/videoplayback", $youtubeData);
                    }
                }
                $youtubeData = json_decode($youtubeData, true);
                if(empty($youtubeData)){
                    $youtubeData = [];
                }
            }else{
                $youtubeData = [];
            }
            $videourl = getYoutubeVideoUrl($youtubeId, $youtubeData);
        }
        if(!$videourl){
            show_error(404);
        }else{
            header('Content-Type: text/plain');
            $url = $urlCoding->encodeUrl($videourl,'video',null,true);
        	if(!empty($config['is_behind_cloudfront']) && !empty($config['sync_server']) && $url && $url[0]=='/' && ($node=get_wildcard_node())){
      		    $url = $node.$url;
        	}
            exit($url);
        }
    case 'ytbl': //youtube播放列表
        $json = '';
        if($youtubeId){
            $json = getYoutubePlaylist($youtubeId);
        }
        if($json) {
            header('Content-Type: application/json; charset=UTF-8');
            header('Cache-Control: public, max-age=86400');
            header('Expires: '.gmtDate("+1 day"));
            header('Access-Control-Allow-Origin: *');
            echo json_encode($json);
            exit;
        }else{
            show_error(404);
        }
    case 'ytbimg': //youtube缩略图片
        $remoteUrl = Url::create("http://i.ytimg.com/vi/{$youtubeId}/0.jpg");
        $_GET[$config['ctype_var_name']] = $ctype = 'img';
        break;
    case 'matomo': //matomo统计功能
		if(authented_ever()){
			//
		}elseif($config['enable_matomo']){
 			require(APPDIR.'/include/matomo.inc.php');
			if($builtInExt=='.js'){
				header('Cache-Control: public, max-age=604800');
				header('Expires: '.gmtDate("+7 day"));
				echo Matomo::getTrackerJs(false);
			}elseif($builtInExt=='.php'){
				header('Cache-Control: no-cache, must-revalidate');
				header('Pragma: no-cache');
				Matomo::submit();
			}
		}
        exit;
    case 'swjs':
        if(!empty($config['disabled_sw'])){
            header('Content-Type: text/javascript; charset=utf-8');
            exit;
        }
        $pwa->outputSwJs($currentUrl, $urlCoding);
        break;
    case 'get_country': //根据ip判断国家
        header('Cache-Control: private, max-age=600');
        echo get_user_country();
        exit;
    default: //未知接口
        if($builtInAction) {
            show_error(404);
        }
}

//形如 /[v,l]30个字母.m3u8 或 /[v,l]30个字母-数字p.m3u8 的干净世界视频网址。形式2里的数字表示只使用此分辨率的资源
$select_m3u8_resolution = null;
if(empty($remoteUrl) && strpos($requestUri,'.m3u8')!==false && preg_match('#^/([vl]\w{30})(?:-(\d+)p)?\.m3u8#', $requestUri, $match)){
    /*
    //暂不禁止ip
    $throughFreegate = isset($_SERVER['HTTP_X_D_FORWARDER']) && $_SERVER['HTTP_X_D_FORWARDER']=='yes';
    $country = get_user_country(false);
    if(!DEBUGING && !$throughFreegate && !in_array($country,array('CN','TW','LOCAL'))){
		show_error(403, '', false, true);
	}
    */
    $error = '';
    $gjInfo = getGanjingVideoUrl($match[1], false, $error);
    $url = ($gjInfo && !empty($gjInfo['video'])) ? $gjInfo['video'] : '';
    if($url && (strpos($url,'.cloudokyo.cloud/')!==false || strpos($url,'.edgefare.net/')!==false)){
        //浏览器出于安全考虑，不允许在跨域请求中进行重定向
        header('Access-Control-Allow-Origin: *');
        header('Content-Type: application/vnd.apple.mpegurl');
        $option = $config;
        $option['follow_location'] = true;
        $s = http_get($url, $option);
        if(strpos($s,'.m3u8')!==false && strpos($s,'#EXT-X-TARGETDURATION')===false){
            //如果内容是m3u8索引，就直接显示内容，但是需要把相对链接转换为完整链接
            $remoteUrl = Url::create($url);
            $s = preg_replace_callback('#^[\w\-\./]+?\.m3u8$#m', function($match){
                global $remoteUrl;
                return $remoteUrl->getFullUrl($match[0]);
            }, $s);
            $s = preg_replace_callback('#\bURI="([\w\-\./]+?\.m3u8)"#', function($match){
                global $remoteUrl;
                return 'URI="' . $remoteUrl->getFullUrl($match[1]) . '"';
            }, $s);
        }else{
            //否则就把这个m3u8嵌套到当前网址里
            $s = "#EXTM3U\n\n#EXT-X-INDEPENDENT-SEGMENTS\n\n#EXT-X-STREAM-INF:BANDWIDTH=0\n{$url}\n";
        }
        echo $s;
        exit;
    }elseif($url){
        $remoteUrl = Url::create($url);
        $_GET[$config['ctype_var_name']] = $ctype = 'media';
        if(!empty($match[2])){
            $select_m3u8_resolution = $match[2];
        }
    }else{
        show_error(404);
    }
}

//形如 /[v,l]30个字母_推广者附加码 的干净世界播放页网址
if(empty($remoteUrl) && preg_match('#^/([vl])(\w{30})(_\w+)?(\?|$)#', $requestUri, $match)){
    $type = $match[1]=='l' ? 'live' : 'video';
    $url = "/zh-CN/{$type}/{$match[2]}" . ($match[3] ? "#sid={$match[1]}{$match[2]}{$match[3]}" : '');
    show_404_redirect($url, false, false, true);
}

//pageid网址，采用firebase实现的页面ID短网址【使用v.php接口生成】
if(empty($remoteUrl) && ($pageidValues=$urlCoding->getPageIdUrl($requestUri))){
    //禁止以ip形式访问pageid
    forbid_ip_server();

    list($pageid, $urlHash, $url) = $pageidValues;
	//处理对v.php的二次调用，改为使用本域名在服务器端完成对v.php的二次调用，需要转发响应头里的Location和Content-Type，转发响应内容
	if(strpos($url, '/v.php?')!==false){
		$query = substr($url, strpos($url,'?')+1);
		if(substr($query,0,5)=='code=' && preg_match('#^code=(\w+)$#', $query, $m)){
			$query = juyuange_decrypt($m[1]);
		}elseif(substr($query,0,2)=='c=' && preg_match('#^https?://([\w\-\.]+)/v\.php\?c=(\w+)$#', $url, $m)){
			$query = juyuange_decrypt($m[2], DEFAULT_JYG_PASSWORD, true, $m[1]);
		}elseif(preg_match('#&(id|api|action)=#', "&{$query}")){
			//
		}else{
			$query = null;
		}
		if($query){
            //由下边的通过http访问v.php，改为用php直接调用v.php
            $sharp = strpos($query,'#');
            if($sharp!==false){
                $query = substr($query,0,$sharp);
            }
            $uriParam = !empty($_GET['uri']) ? $_GET['uri'] : null;
            parse_str($query, $_GET);
            if($uriParam) $_GET['uri']=$uriParam;
            require(APPDIR . '/v.php');
            exit;

            /*
			$option = $config;
			$option['return_header'] = true;
			$option['follow_location'] = false;
			$url = $currentUrl->home.'/v.php?c='.juyuange_encrypt($query, DEFAULT_JYG_PASSWORD, true);
			$response = http_get($url, $option);
			if(substr($response,0,24)=='&#38169;&#35823;&#65306;'){ //错误：没找到任何资源
				if(strpos($query,'redirect')>0){
					parse_str($query, $arr);
					if(isset($arr['action'],$arr['uri']) && $arr['action']=='redirect'){
						$uri = $arr['uri'];
						show_404_redirect($uri, true);
					}
				}
			}elseif(preg_match_all('#((?:HTTP/1\.[01]|Location:|Content\-Type:|Content\-Disposition:|Cache\-Control:|Expires:|Pragma:)\s[^\r\n]+)#i', "\n{$last_http_response_header}\n", $matches, PREG_SET_ORDER)){
                for($i=0, $count=count($matches); $i<$count; ++$i) {
					header($matches[$i][1]);
				}
			}
			echo $response;
			exit;
            */
		}
	}elseif(strpos($url,'//www.szzd.')!==false){
        if(preg_match('#^https?://www\.szzd\.(?:org|io)(/(?:v\.php|faq\.php|mhr\.php|news\.php|video/|tui/|jump/).*)$#', $url, $m)){
            //把www.szzd.org下的某些网址的页面ID跳转到本站网址，为的是利用页面ID的统计功能
            show_404_redirect($m[1], false);
        }else{
            //404
            show_error(404);
        }
    //针对github，把错误的%23转换为#
    }elseif(strpos($url, '//raw.githubusercontent.com')!==false && strpos($url, '%23')!==false){
        $url = str_replace('%23', '#', $url);
    }

    //修复干净世界网址（替换域名）
    $gjw = repair_ganjing_url($url, true, false);
    if($gjw) {
        $url = $gjw;
    }
    //如果是形如/zh-CN?tab=cat19的网址，需要保证代理网址里也包含这个，否则这个分类将无法起作用
    if(strpos($url,'ganjingworld.com/')!==false && strpos($currentUrl->original,'tab=cat')===false && preg_match('#/(?:zh-[\w+/]+|)\?(tab=cat\d+)$#',$url,$match)){
        $url = $urlCoding->encodeUrl($url, null, null, true);
        $url .= (strpos($url,'?')===false ? '?' : '&') . $match[1];
        show_cookie_redirect($url, true);
    }

    //检查onlycn限制
    if(substr($url,-7)=='?onlycn'){
        $url = substr($url,0,-7);
        if(!in_array(get_user_country(false),array('CN','LOCAL'))){
            if(substr($_SERVER['HTTP_ACCEPT'],0,10)=='text/html,'){
                show_error(403, "此网址仅允许中国大陆用户访问", true, true);
            }else{
                show_error(403, '', false, true);
            }
        }
        //禁止cdn缓存
    	header('Cache-Control: no-cache, must-revalidate');
    	header('Pragma: no-cache');
        header('Access-Control-Allow-Origin: *');
        header('Edge-Control: no-store, bypass-cache');
    }

	//使用原始请求里的url参数值（一般是源网站的相对网址）修改页面ID的原网址
	if(!empty($_GET['url'])) {
		$url = Url::create($url)->getFullUrl($_GET['url']);
	}

    //检查hash尾巴
    $hasValidHash = check_url_hash($requestUri, null, !empty($urlHash));
    //允许不跳转直接访问的几种情形。如果是网页就总是应该跳转，因为有些链接依赖referer网址才能正确还原，
    $directAccess = ($hasValidHash || get_app_uid() || preg_match('#^/'.$pageid.'\.\w{3,4}$#',$requestUri)) &&
        (
            preg_match('#\.(mp3|mp4|m3u8|ts|webm|jpg|gif|png|svg|ico|apk|json)(\?|\#|$)#',$url) ||
            strpos($url, '://radio.soundofhope.org')!==false ||
            strpos($url, '://livecast2.soundofhope.org')!==false
        );

	if(!$hasValidHash && !$directAccess){
        $url = $urlCoding->encodeUrl($url, null, null, true);
        if($config['enable_matomo']){
            $url .= "#sid={$pageid}";
        }
        show_404_redirect($url, false);
	}

	//把明慧广播的高品质音频链接替换为16k网址
	if(strpos($url,'mhradio.org/')!==false && preg_match('#^https?://(\w+\.)?mhradio\.org/news_images(/audio.+?)(\.mp3)$#', $url, $m)){
		$url = "http://mms.hungfa.net{$m[2]}_16k{$m[3]}";
	}

	if($directAccess){
		$remoteUrl = Url::create($url);
        if($urlCoding->isSafeDomain($remoteUrl->host)){
            show_redirect($url);
        }
	}else{
		$endWithResExt = false;
		if(strpos($url,'?')===false){
			$ext = fileext($url);
			if(!empty($ext) && strpos($extlist['all_res']," $ext ")!==false){
				$endWithResExt = true;
			}
		}

		//如果v.php调用服务被滥用，下边这种跳转是否能避免被作为特征
		$url = $urlCoding->encodeUrl($url, null, null, true);

		if($config['enable_matomo'] && !$endWithResExt){
			$url .= "#sid={$pageid}";
		}
		show_redirect($url);
	}
}

// ================================================================================================
// 解析真实的远端url
// ================================================================================================

if(!$ctype){
    $ctype = isset($_GET[$config['ctype_var_name']]) && preg_match('#^[\w\-\.]+$#', $_GET[$config['ctype_var_name']]) ? $_GET[$config['ctype_var_name']] : '';
}
if(!$ctype && $ext){
	switch($ext){
        case '.htm':
        case '.html':
            $ctype = 'html';
            break;
        case '.xml':
            $ctype = 'xml';
            break;
        case '.jsonp':
        case '.json':
        case '.js':
            $ctype = 'js';
            break;
        case '.css':
            $ctype = 'css';
            break;
        default:
        	if(strpos($extlist['image']," {$ext} ")!==false){
                $ctype = 'img';
        	}elseif(strpos($extlist['all_media']," {$ext} ")!==false){
                $ctype = 'media';
        	}elseif(strpos($extlist['download']," {$ext} ")!==false){
                $ctype = 'resource';
            }
            break;
    }
}
$isframe = $ctype=='frame';
$isImport = $ctype=='import';
$accept = isset($_SERVER['HTTP_ACCEPT']) ? $_SERVER['HTTP_ACCEPT'] : 'text/html';
$isajax = isset($_SERVER['HTTP_X_REQUESTED_WITH']) && $_SERVER['HTTP_X_REQUESTED_WITH']=='XMLHttpRequest';

//在响应前先判断是否可能是顶层的网页
if( ($ctype && $ctype!='html') ||
    $isframe || $isajax || $isImport ||
    (isset($_SERVER['HTTP_SEC_FETCH_DEST']) && !in_array($_SERVER['HTTP_SEC_FETCH_DEST'],['document','empty'])) ||
    strpos($accept,'text/html')!==0
){
	$is_top_page = false;
}elseif(!$ext && strpos($accept,'text/html')===0){
	$is_top_page = true;
}elseif($ext){
	$contentType = get_content_type($ext);
	$is_top_page = $contentType && isset($supported_content_type[$contentType]) && $supported_content_type[$contentType]=='html';
}else{
    $is_top_page = false;
}

//是/tui/开头的三退网址
if(empty($remoteUrl) && !empty($config['tui_url']) && substr($requestUri,0,5)=='/tui/' && preg_match('#^/tui/(\?\w{8,10})?$#',$requestUri)){
    //获取三退表单系统源网址
    $remoteUrl = Url::create($currentUrl->getFullUrl($config['tui_url'] . substr($requestUri,5), true));
    //跳转
    if(!check_url_hash($requestUri)){
        header('Access-Control-Allow-Origin: *');
        show_404_redirect($requestUri, true);
    }
}

//解析远端地址
if(empty($remoteUrl)){
	$remoteUrl = $urlCoding->getRemoteUrl(null,true,true);
	if($remoteUrl && $remoteUrl->file=='TEST_STATIC_FOR_ATS.png'){
	    echo 0;
	    exit;
    }elseif($remoteUrl && !empty($_SERVER['HTTP_X_FORWARD_S'])){
        //尝试跳转到相同源网址的另一个代理域名，具体哪些应该跳转，是在swjs里决定，依据的是它的请求头
        $pwa->forward202($remoteUrl->url);
	}elseif($remoteUrl===false && $is_top_page && preg_match('#^/\w{4,8}(?:/?\?[0-9a-f]{8,10})?$#', $requestUri)){
        //如果网址解密失败，并且可能是顶层的pageid页，很可能是因为pageid服务故障，就显示pwa页吧，但是需要尽量避免再出现pageid网址
		$pwa->outputWebpage($currentUrl, $urlCoding);
        //如果没成功输出PWA页面，就继续显示404错误页
        show_error(404);
	}elseif($remoteUrl===false){
		show_error(404);
	}elseif(!preg_match('#^[\w\-\.]+$#', $remoteUrl->host)){
		show_error(400);
	}
    //如果源网址是szzd.org的数字网址或页面id，就跳转到本站
    if($remoteUrl && (in_array($remoteUrl->host,['www.szzd.org','szzd.org','www.szzd.io','szzd.io']) || substr($remoteUrl->host,0,13)=='www.szzd.org.' || substr($remoteUrl->host,0,12)=='www.szzd.io.') && preg_match('#^/(\d+|\w{4,8})(\?\w+)?$#', $remoteUrl->uri)){
        show_redirect($remoteUrl->uri);
    }
}

//如果源站是三退表单，为了使此系统实现直接访问时加密但被站外调用时不加密，所以当在站外调用时加了一个请求头
if($remoteUrl && !empty($config['tui_url']) && strpos($remoteUrl->url,$config['tui_url'])===0){
    header('Access-Control-Allow-Origin: *');
    $config['additional_http_headers']['X-From-Phproxypro']='1';
    $config['is_proxy_for_tui'] = true; //用于matomo的频道
}

$urlCoding->remoteUrl = $remoteUrl;
$_SERVER['REMOTE_URL'] = $remoteUrl->url;
$redirect_original = !empty($config['redirect_original']) && preg_match("#{$config['redirect_original']}#", $remoteUrl->url);

//根据黑名单白名单检查是否被block (不阻止常见的在线资源文件)
$ext = fileext($remoteUrl->file);
if($urlCoding->isBlockDomain($remoteUrl->host)){
	show_error(403);
}elseif((in_array($ext,['.js','.json','.jsonp']) || $accept=='*/*' || strpos($accept,'javascript')!==false) && $urlCoding->isBlockScript($remoteUrl->url)){
	show_error(403);
}elseif($isajax || substr($accept,0,9)!='text/html' || strpos(" {$extlist['all_res']} {$extlist['jscss']} ", " $ext ")!==false){
	//不是网页请求，继续
}elseif($urlCoding->isSafeDomain($remoteUrl->host)){
	//安全域名，继续
}elseif(!$urlCoding->isBlockedByWhiteDomain($remoteUrl->host)){
	//未被白名单阻止，继续
}else{
	//被白名单阻止
	show_error(403);
}

//禁止蜘蛛访问
if(!preg_match('#(feed|\.xml$|\.rss$)#', $remoteUrl->url)){ //避免把rss reader网站阻止
    forbid_spider();
}

//检查只允许中国大陆访问的url
if(!empty($config['only_allow_cn'])){
    check_onlycn($remoteUrl, $ctype);
}

/*检查是否只允许中国大陆播放新唐人直播
$ntdtv_app_China = false;
if( strpos($remoteUrl->file,'.m3u8')!==false &&
    preg_match('#\.(ntdtv\.com|ntdtv\.com\.tw|ntdimg\.com)/.+?\.m3u8#', $remoteUrl->url) &&
    file_exists(DATADIR.'/ntd_onlycn.dat'))
{
    if(!in_array(get_user_country(false),array('CN','LOCAL'))){
        show_error(403, '', false, true);
    }else{
        $ntdtv_app_China = file_get_contents(DATADIR.'/ntd_onlycn.dat')==='APP';
        if($ntdtv_app_China && !get_app_uid()){
            show_error(403, '', false, true);
        }
    }
}
*/

//检查前端是否支持hook ajax，CF域名因为历史响应标头策略的限制无法支持，googlevideo是视频请求也不hook
if(DEBUGING<2 && !in_array($currentUrl->root, ['cloudfront.net','googlevideo.com'])){
    hookajax_check_request($_SERVER['REQUEST_URI'], $remoteUrl->script);
}

//禁止访问serviceWorker js文件
if(isset($_SERVER['HTTP_SERVICE_WORKER']) && $_SERVER['HTTP_SERVICE_WORKER']=='script'){
    if(empty($_SERVER['HTTP_SEC_FETCH_DEST']) || $_SERVER['HTTP_SEC_FETCH_DEST']=='serviceworker'){
        show_error(404, '', false, false);
    }
}

//针对特定网站
//===========================================================================================================

$error_message_403 = null;
$new_useragent = null;
$response_text = null;
$php_input_data = null;

//代理youtube时
if($remoteUrl->root=='youtube.com'){
    //代理youtube时都用chrome，否则某些内容无法被正确处理
	$new_useragent = CHROME_UA_PC;

    //如果是首页就改为新唐人频道页，因为代理无法开启播放历史导致了首页空白
    if($remoteUrl->uri=='/' || substr($remoteUrl->uri, 0, 5)=='/?hl='){
        $remoteUrl = Url::create($remoteUrl->home . '/@NTDCHINESE/videos#ytb_home');
    }elseif($remoteUrl->uri=='/@NTDCHINESE/videos?cbrd=1&ucbcb=1'){
        $remoteUrl->fragment = 'ytb_home';
    }
//希望之声和禁书网的检测白名单
}elseif(in_array($remoteUrl->root, ['soundofhope.org','aboluowang.com','bannedbook.org','edgefare.cloud','tuidang.org'])){
	$new_useragent = "{$_SERVER['HTTP_USER_AGENT']} (PHProxyPro-nYG7DINFjbuF)";
//干净世界
}elseif(in_array($remoteUrl->root, ['ganjing.com','ganjing.io','ganjingworld.com',])){
    if(preg_match('#^(/zh-CN|/zh-TW|)/gjwplus(/|$)#', $remoteUrl->script)){
        $response_text = "此页需要从官网访问： <a href='{realurl}{$remoteUrl->url}' target='_blank'>{realurl}{$remoteUrl->url}</a>";
    }elseif(preg_match('#^/_next/data/\w+(/zh-CN|/zh-TW|)/gjwplus/#', $remoteUrl->script)){
        show_error(403, '此页需要从官网访问', true);
    }
    //检测白名单
	$config['additional_http_headers']['X-GJW-AUTH'] = 'szmj-9555-41e4-8a93-f777';
    //把嵌入播放页跳转到v.php
    redirect_ganjing_embed($remoteUrl);
}

//禁止某些网站显示底部导航条
if(in_array($remoteUrl->root,['ganjing.com','ganjing.io','ganjingworld.com','shenyun.com','shenyunperformingarts.org','falundafa.org'])){
    $bottom_navigation['enable'] = false;
}

//请求youtube嵌入视频页
if(in_array($remoteUrl->host, ['www.youtube.com','m.youtube.com','www.youtube-nocookie.com']) &&
	preg_match('#^/embed/([\w\-\.]+)(?:\?list=([\w\-\.]+)|\?.*|$)#', $remoteUrl->uri, $match))
{
	$listId = !empty($match[2]) ? $match[2]: null;
	$videoId = $match[1];
    $head = '<style type="text/css">html,body{margin:0;padding:0;width:100%;height:100%;}</style><script type="text/javascript" src="/images/jwplayer.js"></script>';
	$body = '<script type="text/javascript">';
	if($listId){
		$url = "/?{$builtInName}=" . encrypt_builtin("_ytbl_{$listId}");
		$body .= "playYtbList('{$listId}','{$videoId}',false,'100%','100%','','{$url}');";
	}else{
		$videoUrl = "/?{$builtInName}=" . encrypt_builtin("_ytb_{$videoId}");
		$thumbUrl = encrypt_builtin_images_url("_ytbimg_{$videoId}",'.jpg');
		$body .= "playYtb('{$videoId}',false,'100%','100%','','{$videoUrl}','{$thumbUrl}');";
	}
	$body .= '</script>';
    echo get_fullpage($head, $body);
	exit;
}

//针对特定404显示pwa页
if($remoteUrl->uri=='/404.htm' && in_array($remoteUrl->host,['www.szzd.org','szzd.org','www.szzd.io','szzd.io'])){
	$pwa->outputWebpage($currentUrl, $urlCoding);
}

//当在cf域名下时，禁止直接代理访问youtube、youmaker等视频网站的网页，如果有泛域名就用泛域名访问，否则就禁止访问
if(!empty($config['is_behind_cloudfront']) && should_redirect_cf_to_wild($remoteUrl, $ctype, $iswebpage)){
    if(!empty($config['sync_server'])){
        //如果设置了中心服务器，就尝试获取泛域名访问youtube
        show_wildcard_redirect($remoteUrl->url, $iswebpage, false, false);
        //如果没找到泛域名节点，就提示稍后再试
        show_error(404, '', false, true);
    }else{
        //否则禁止直接访问
        show_error(403, '无法访问这个网站', $is_top_page);
    }
//禁止访问的域名
}elseif(in_array($remoteUrl->host, ['webmail.minghui.org']) || in_array($remoteUrl->root, ['tiandixing.org'])){
    if($is_top_page){
        $ctype = 'html';
        $response_text = "这个服务不允许访问这个网站，请用其它翻墙方式访问官网：{realurl}{$remoteUrl->url}";
    }else{
        show_error(403, '', true);
    }
//响应明慧的限制
}elseif($remoteUrl->root=='minghui.org' && (strpos($remoteReferer,'dongtaiwang.com/')===false) && ($checkUrl=mh_get_check_url($remoteUrl,$remoteReferer))){
    $remoteUrl = Url::create($checkUrl);
    if($is_top_page){
        $error_message_403 = '这个服务不允许访问这个栏目的文章，请用其它翻墙方式访问官网：{realurl}' . str_replace('/client=sz', '', $remoteUrl->url);
    }
/*
}elseif($ntdtv_app_China){
    //中国大陆用户在app里访问新唐人直播
    $http->setRequestHeader('user-agent', "{$_SERVER['HTTP_USER_AGENT']} (PHProxyPro-SzzdAPP)");
*/
}elseif(in_array($remoteUrl->root,['ganjing.com','ganjing.io','ganjingworld.com'])){
    //干净世界只允许大陆ip或者自由门访问
    $throughFreegate = isset($_SERVER['HTTP_X_D_FORWARDER']) && $_SERVER['HTTP_X_D_FORWARDER']=='yes';
    $notTestgjw = empty($_COOKIE['testgjw']);
    if($is_top_page && $notTestgjw && !DEBUGING && empty($config['is_local_test']) && !$throughFreegate && (($country=get_user_country(false,true))===false || !in_array($country,array('CN','TW','LOCAL')))){
        header('Cache-Control: no-cache, must-revalidate');
        header('Pragma: no-cache');
        $ctype = 'html';
        $response_text = "中国大陆之外的用户，请直接<span ondblclick='document.cookie=\"testgjw=1\";location.reload();'>访问</span>官网： <a href='{realurl}{$remoteUrl->url}' target='_blank'>{realurl}{$remoteUrl->url}</a>";
    }elseif($remoteUrl->path=='/404/'){
        //停止显示404等错误页（特别是会再跳转的网址）
        header('X-Location: '.$remoteUrl->path);
        show_error(404);
    }elseif(in_array($currentUrl->uri,['/','/zh-CN','/zh-CN/','/zh-TW','/zh-TW/'])){
        $url = $urlCoding->encodeUrl($remoteUrl->home . ($remoteUrl->host=="www.ganjingworld.com" ? '/zh-CN' : '/'), null, null, true);
        show_cookie_redirect($url, true);
    }else{
        //修复干净世界网址（仅替换常见网页的域名）
        $gjw = repair_ganjing_url($remoteUrl->url, true, true);
        if($gjw) {
            $remoteUrl = Url::create($gjw);
        }
        //如果是形如/zh-CN?tab=cat19的网址，需要保证代理网址里也包含这个，否则这个分类将无法起作用
        if(strpos($currentUrl->original,'tab=cat')===false && preg_match('#^/(?:zh-[\w+/]+|)\?(tab=cat\d+)$#',$remoteUrl->uri,$match)){
            $url = $urlCoding->encodeUrl($remoteUrl->url, null, null, true);
            $url .= (strpos($url,'?')===false ? '?' : '&') . $match[1];
            show_cookie_redirect($url, true);
        }
    }
}

//转到对应的手机页面
if($config['redirect_to_mobile'] && Http::isMobile() && isset($mobile_domains[$remoteUrl->url])){
    $url = $urlCoding->encodeUrl($mobile_domains[$remoteUrl->url], null, null, true);
    show_404_redirect($url,true);
}

//判断是否使用cookie
if(!$config['enable_cookie'] && should_force_cookie($remoteUrl, $ctype)){
    $config['enable_cookie'] = true;
}

//cookie
$requestCookieCoding = new CookieCoding($remoteUrl);
if($config['enable_cookie']){
	$requestCookieCoding->readCookies();
	if (isset($_POST[$config['basic_auth_var_name']], $_POST['username'], $_POST['password'])) {
		$_SERVER['REQUEST_METHOD'] = 'GET';
		$requestCookieCoding->remoteAuth = base64_encode(trim($_POST['username']) . ':' . $_POST['password'] );
		unset($_POST);
		$requestCookieCoding->writeCookies(array()); //因为要保存auth认证信息，所以必须调用这个方法
	}
}

// ================================================================================================
// 本次请求和响应结果变量
// ================================================================================================

/** @var array */
$page = [
	//请求是否是动态载入的（不缓存）
	'isajax' => isset($_SERVER['HTTP_X_REQUESTED_WITH']) && stripos($_SERVER['HTTP_X_REQUESTED_WITH'],'XMLHttpRequest')!==false,
    //此网页或资源的类型(html, css, js, xml, img, media, embed, video, resource, param, content-type里的类型)
	'ctype' => $ctype && !$isframe ? $ctype : '',
	//是否frame或iframe页面
	'isframe' => $isframe,
	//是否是通过 link rel="import" 导入的页面
	'isimport' => $isImport,
	//是否是$supported_content_type里设置的需要处理的类型，这些类型需要处理后一次性返回，除此之外的其他类型会分块儿返回
	'supported' => false,
	'pageandjs' => false,
	//文本类型(包含supported=true的和其他的文本类型)
	'istext' => false,
	//是否优先读取缓存，没有缓存时才向远端服务器请求（在下边确定了远端URL之后才能确定）
	'readcache' => false,
	//远端服务器返回的结果是否应该写入缓存（在远端服务器返回HTTP头之后才能确定）
	'writecache' => false,
	//本地缓存扩展名，只有不带查询参数的资源文件才使用实际的扩展名，其他的都统一使用 .~tmp
	'cacheext' => null,
	//网页字符集
	'charset' => null,
	//临时存储完整的文本形式的HTTP响应体
	'data' => '',
	//是否已经输出响应头
	'responsed' => false,
	//当前为此用户分配的cnd的编号列表
	'cdn' => isset($_COOKIE['_cdn_']) && preg_match('#^[\d,]+$#', $_COOKIE['_cdn_']) ? $_COOKIE['_cdn_'] : '',
];

/** @var CacheHttp|null 负责把远端服务器返回的结果写入缓存的缓存对象（在下边接收到http头时判断）*/
$cache = null;

//显示指定网页内容
if($response_text){
    outputText(get_fullpage('', $response_text), true, null);
    exit;
}

if($config['enable_cache'] && isset($_SERVER['HTTP_REFERER']) && strpos($_SERVER['HTTP_REFERER'],'.swf')>0){
	//当被flash下载时，很有可能是在线播放，此时不限制文件大小
	$config['max_file_size']=0;
	//当flash里要下载的文件包含动态参数时，禁用缓存机制
	if(!empty($remoteUrl->query)){
		$config['enable_cache']=false;
	}
}

//某些域名禁止在本地被缓存（图片、js和css依然会被缓存）
if( $config['enable_cache'] && $nocache_domains_pattern &&
	!in_array($ctype,['css','js','img']) && (!$ext || strpos($extlist['image'].$extlist['jscss'], " $ext ")===false) &&
    preg_match($nocache_domains_pattern, $remoteUrl->host)
){
	$config['enable_cache']=false;
}

//伪静态化资源文件
if( $config['enable_cache'] &&
	strpos($requestUri,$currentUrl->path.'files/')===0 &&
	preg_match('#^/files/(?:\w{16}-\w-[\w\-]+|'. $config['url_var_name'][0] .'/\w{32}/[\w/]+)(\.\w{2,4})(\?[^=]*)?$#',$requestUri,$match))
{
	//记录缓存选项
	$ext=$match[1];
	$page['cacheext']=$ext;
	$page['readcache']=true;
	//ctype
	if(!$page['ctype'] && strpos($extlist['all_res'], $ext)!==false){
		$page['ctype']='resource';
	}
}

//以下情况都同时满足时才会读取缓存
//1. 开启了缓存机制，或者是js文件（有的大js会频繁的被使用）
//2. 没有：提交GET表单、提交POST表单、上传文件、使用了域登录
//3. 不发送cookie，或者是资源文件（只有应该被浏览器缓存的资源文件才会写入缓存）
$page['readcache'] =
	($config['enable_cache'] || (DEBUGING==0 && (($page['ctype']=='js' && $ext!='.json') || $page['ctype']=='css'))) && !isset($_COOKIE['_no_cache_']) &&
	(empty($_GET[$config['get_form_name']]) && empty($_POST) && empty($_FILES) && empty($requestCookieCoding->remoteAuth)) &&
	(empty($requestCookieCoding->remoteCookies) || preg_match($resource_ctype,$page['ctype']) || $page['cacheext'] || !empty($_SERVER['HTTP_IF_NONE_MATCH']));

/*
//客户端缓存机制（本机制即使未开启本地缓存也有效）：1小时内的重复请求，如果cookie没有变化，就返回304（禁止缓存的内容除外）
//因为只根据HTTP_IF_MODIFIED_SINCE判断是否需要缓存，会导致某些短时间的缓存无法失效，所以要禁用以下代码，此机制改为用 Cache-Control:max-age=秒 来控制
if(DEBUGING<2){
	$modifiedSince = isset($_SERVER['HTTP_IF_MODIFIED_SINCE']) ? strtotime($_SERVER['HTTP_IF_MODIFIED_SINCE']) : null;
	if($modifiedSince && TIME-$modifiedSince<=3600){
		if(isset($_SERVER['HTTP_IF_NONE_MATCH'])){
			$etag = CacheHttp::makeEtag(serialize($requestCookieCoding->remoteCookies).strval(Http::isMobile()).$page['cdn']);
			if($etag==$_SERVER['HTTP_IF_NONE_MATCH']){
				header('HTTP/1.1 304 Not Modified');
				exit;
			}
		}else{
			header('HTTP/1.1 304 Not Modified');
			exit;
		}
	}
}
*/

// ================================================================================================
// 定义当远端服务器或者文件缓存返回内容时的应对操作
// ================================================================================================

/**
 * 完整返回HTTP头部之后的事件
 * @param Http $http
 * @param array $headers 解析后的数组格式（键名都是小写）
 * @param bool $cacheId 缓存id
 */
function onReceivedHeader($http, $headers, $cacheId){
	global $config, $page, $supported_content_type, $requestCookieCoding, $currentUrl, $remoteUrl, $urlCoding,
        $redirect_original, $cache, $extlist, $is_behind_cdn, $requestUri, $is_top_page;
    set_time_limit_ex($config['connect_timeout']+$config['read_timeout']+10);
	//如果发生了转向
	$originalRemoteUrl = $remoteUrl;
	$redirected = $http->getLastUrl()!='' && $http->getLastUrl()!=$remoteUrl->url;
	if($redirected){
		$remoteUrl=Url::create($http->getLastUrl());
		if($remoteUrl===false){
			show_error(404);
		}elseif(!preg_match('#^[\w\-\.]+$#', $remoteUrl->host)){
			show_error(400);
		}
		$urlCoding->remoteUrl=$remoteUrl;
	}
	//==判断资源类型==
	$ext = isset($headers['__ext']) ? $headers['__ext'] : fileext($remoteUrl->file);
    if(!$ext) $ext = fileext($currentUrl->file);
	if((!$http->contentType || $http->contentType=='application/octet-stream') && $ext){
		$type = get_content_type($ext);
		if(strpos($type,'text/')===0){
			$http->contentType = $type;
		}
	}elseif(!$http->contentType && $remoteUrl->query=='' && $ext){
		$http->contentType = get_content_type($ext);
		if(!isset($headers['content-type']) && $http->contentType) $headers['content-type']=$http->contentType;
	}elseif($http->contentType && strpos($http->contentType,'text/')===0 &&
		$http->contentLength>5*1024*1024 &&
		$ext && ($type=get_content_type($ext)) && in_array(substr($type,0,6), array('audio/','video/'))){
		//有些影音文件返回的content-type是文本，这里将把超过5M的这类文件修正为影音文件
		$http->contentType = $type;
	}elseif($http->contentType && strpos($http->contentType,'application/signed-exchange')===0){
		//禁用sxg证书交换
		$headers['content-type'] = $http->contentType = 'text/html';
		$page['supported'] = true;
		$headers['__ctype'] = $page['ctype'] = $ctype = 'html';
	}elseif($http->contentType && strpos($http->contentType,'text/plain')==0 && $remoteUrl->host=='raw.githubusercontent.com'){
        //把github的有些网址转换为实际的content-type
        if (($ext=='.htm' || $ext=='.html') && ($remoteUrl->query=='htm' || $remoteUrl->query=='html')){
            $http->contentType = 'text/html';
            $headers['content-type'] = str_replace('plain', 'html', $headers['content-type']);
        }elseif($ext=='.js'){
            $http->contentType = 'text/javascript';
            $headers['content-type'] = str_replace('plain', 'javascript', $headers['content-type']);
        }elseif($ext=='.json'){
            $http->contentType = 'text/json';
            $headers['content-type'] = str_replace('plain', 'json', $headers['content-type']);
        }
    }elseif($http->contentType && in_array($http->contentType, ['application/x-mpegurl', 'application/vnd.apple.mpegurl'])){
        $page['istext'] = true;
        $page['ctype'] = 'm3u8';
    }

	if($ext=='.woff' || $ext=='.woff2'){
	    $ctype = 'img';
	    $headers['content-type'] = 'font/woff2';
	}elseif(isset($headers['__ctype'])){
		$ctype = $headers['__ctype'];
	}elseif(isset($supported_content_type[$http->contentType])){
		$ctype = $supported_content_type[$http->contentType];
	}elseif(in_array(substr($http->contentType,0,6), array('audio/','video/'))){
		$ctype = 'resource';
	}else{
		$ctype = $http->contentType;
	}

	//把类似 application/json+protobuf 简化为 application/json 以便判断
	if(!$page['ctype'] && preg_match('#^(?:text|application)/\w+\+#',$ctype,$match)){
		$ctype = substr($match[0],0,-1);
		if(isset($supported_content_type[$ctype])){
			$ctype = $supported_content_type[$ctype];
		}
	}
	if(!$page['ctype'] || in_array($ctype, $supported_content_type)){
		$page['ctype'] = $ctype;
	}elseif($page['ctype']=='html' && $ctype=='resource' && $http->contentLength>5*1024*1024){
		//有些影音文件被网址里的ctype指定为网页了，这里将把超过5M的这类文件修正为影音文件
		$page['ctype'] = $ctype;
	}
	$page['supported'] = in_array($page['ctype'], $supported_content_type);
	$page['pageandjs'] = ($page['supported'] && $page['ctype']!='css') || $page['isajax'];
	$page['istext'] = ($page['supported'] || strpos($page['ctype'], 'text/')===0 || $page['ctype']=='m3u8') && (substr($remoteUrl->file,-3)!='.ts');
	$page['charset'] = $http->charset;
	if($page['istext'] && substr($remoteUrl->file,-3)=='.js') $page['ctype'] = 'js';

	//根据Sec-Fetch-Dest纠正网址类型
	if($page['ctype']=='html' && !empty($_SERVER['HTTP_SEC_FETCH_DEST'])){
		switch($_SERVER['HTTP_SEC_FETCH_DEST']){
			case 'image':
			case 'font':
				$page['ctype'] = $ctype = 'img';
				$page['istext'] = false;
				break;
			case 'audio':
			case 'video':
			case 'object':
			case 'embed':
				$page['ctype'] = $ctype = 'video';
				$page['istext'] = false;
				break;
			case 'manifest':
                $page['ctype'] = $ctype = 'manifest';
				break;
			case 'script':
				$page['ctype'] = $ctype = 'js';
				break;
			case 'style':
				$page['ctype'] = $ctype = 'css';
				break;
            case 'iframe':
                $page['isframe'] = true;
                break;
		}
	}

	//返回的content-type是文本类型，实际根据扩展名可以确定为不是文本型的，要纠正过来
	if($page['istext'] && in_array($ext, array('.woff','.woff2','.ttf','.font'))){
		$page['istext'] = false;
	}
	if($page['istext'] && strpos($extlist['all_res']," {$ext} ")!==false){
	    $page['istext'] = false;
	}
	if($page['istext']){
	   unset($headers['content-disposition']);
	}else{
        $is_top_page = false;
    }

    //针对源网站特殊处理
    if($remoteUrl->host=='gw.ganjingworld.com' && in_array($remoteUrl->file, ['index-m3u8', 'get-video-key'])){
        //禁止干净世界的这两个m3u8相关的缓存
        header('Cache-Control: no-cache, must-revalidate');
        header('Pragma: no-cache');
    }

	//需要缓存或传递的响应头
    $cacheable_keys = [
        'content-type', 'expires', 'cache-control', 'etag', 'last-modified', 'pragma', 'content-disposition',
        'location', 'refresh', 'content-language', 'accept-ranges',
    ];
    $forward_keys = array_merge($cacheable_keys, ['content-range']);
    //后续加密和压缩时都会改变长度，所以要避开这些情况
	if((!$page['supported'] && !$page['istext'] && $ext!='.m3u8' && !$http->shouldUnzip) || $_SERVER['REQUEST_METHOD']=='HEAD'){
		$forward_keys[] = 'content-length';
	}
	if($config['enable_cookie']){
		$forward_keys[]='set-cookie';
	}
    //删除无需传递的响应头
	foreach ($headers as $k=>$v){
		if(!in_array($k, $forward_keys) && substr($k,0,15)!='access-control-') unset($headers[$k]);
	}

	if($cacheId){
		//==从缓存输出, 先检查客户端缓存是否依然有效==
		if(!CacheHttp::isModified($headers)){
		    //客户端无需更新，直接发送304信息
			header('HTTP/1.1 304 Not Modified');
            foreach($headers as $k=>$v){
                header(ucwords($k,'-') . ': ' . $v);
            }
			header("X-Cache: HIT {$cacheId}");
            header('Access-Control-Allow-Origin: *');
			$http->stop();
			exit;
		}else{
			if(!isset($headers['content-type']) && $http->contentType) $headers['content-type']=$http->contentType;
		}
	}else{
		//==从HTTP输出==
		//转到域名认证
		if($http->getResponseStatusCode()==401 && isset($headers['www-authenticate']) && preg_match('#basic\s+(?:realm="(.*?)")?#i', $headers['www-authenticate'], $match)) {
			$http->stop();
			show_error(401, $match[1], true);
		}
		//编码HTTP头里出现的url
		if(isset($headers['location'])) {
		    $headers['location']=$redirect_original?$headers['location']:$urlCoding->encodeUrl($headers['location'], null, null, true);
		}
		if (isset($headers['refresh']) && preg_match('#([0-9\s]*;\s*URL\s*=)\s*(\S*)#i', $headers['refresh'], $matches )){
			$headers['refresh']=$matches[1]. $urlCoding->encodeUrl($matches[2], $page['ctype'], null, true);
		}
		//去掉可能的敏感信息
		if(isset($headers['content-disposition'])){
			$headers['content-disposition']=preg_replace('#(filename\s*=\s*["\']?)([^\."\'\s;]+)\.#',
			    'filename='.substr(md5($remoteUrl->url),0,8).'.',
				$headers['content-disposition']);
		}
		if(!$config['enable_cookie']){
			unset($headers['set-cookie']);
		}

		//以下情况满足时应该写入缓存
		//   不是从缓存返回的内容，不是本地调试模式local_debuging
		//1. 开启了缓存机制，或者是非调试模式下的js和css
		//2. 没有：提交GET表单、提交POST表单、上传文件、使用了域登录
		//3. HTTP状态码=200
		//4. 未使用分块下载 (分块下载无法保存到缓存)
		//5. 没发送cookie的网页，或者是应该被浏览器缓存的资源文件才会写入缓存
		//6. 根据HTTP响应头和是否网页或js判断需要缓存的时间长度，网页和js可能包含时效性较强的内容所以最多缓存1小时，其他文件最多缓存1天
		//7. 小于20M
		//8. 排除：QueryString比较长、响应Cache-Control是private且max-age小于1天
		$cacheSeconds = 0;
		$haveCookie = $config['enable_cookie'] && (!empty($requestCookieCoding->remoteCookies) || !empty($headers['set-cookie']));
		$page['writecache'] = !$config['local_debuging'] &&
		    ($page['readcache'] || (DEBUGING==0 && ($page['ctype']=='js' || $page['ctype']=='css' || $ext=='.woff'))) &&
			(empty($_GET[$config['get_form_name']]) && empty($_POST) && empty($_FILES) && empty($requestCookieCoding->remoteAuth)) &&
			$http->getResponseStatusCode()==200 && empty($_SERVER['HTTP_RANGE']) &&
			($page['istext'] || $http->contentLength<=$config['enable_cache']*1048576) &&
			($cacheSeconds=CacheHttp::shouldCache($headers,$page['pageandjs'],$haveCookie)) && $cacheSeconds>0 &&
			$http->contentLength<20*1024*1024 &&
			!(strlen($remoteUrl->query)>20 && $cacheSeconds<86400 && isset($headers['cache-control']) && strpos($headers['cache-control'],'private')!==false);
		if($page['writecache']){
		    //如果是空文件，为避免出错，需要缩短缓存时间，暂定为5分钟
		    if($http->contentLength==0){
		        $cacheSeconds=300;
		    }
			//js文件里，如果服务器没返回过期时间或者很短，需要把缓存有效时间设置的短一些，我们暂定为2小时，并且不能使用.js扩展名以避免不走PHP
			if($page['supported']) $page['cacheext']=null;
			if(!isset($headers['expires'])) $headers['expires']=gmtDate("+{$cacheSeconds} seconds");
			if(!isset($headers['cache-control'])) $headers['cache-control']="public, max-age={$cacheSeconds}";
			//设置缓存信息
			$headerToCache = ['CACHE_VER'=>APP_VER];
			if(!$page['cacheext']){
                foreach ($headers as $k=>$v){
                    if(in_array($k, $cacheable_keys) || substr($k,0,15)=='access-control-') $headerToCache[$k] = $headers[$k];
                }
				$headerToCache['__ctype'] = $page['ctype'];
				$headerToCache['__charset'] = $http->charset;
				if(isset($headers['last-modified'])){
					$headerToCache['__last-modified'] = $headers['last-modified'];
				}
				if(isset($headers['etag'])){
					$headerToCache['etag'] = $headerToCache['__etag'] = $headers['etag']; //原始etag
				}else{
					$arr = $headerToCache;
					unset($arr['expires']);
					$headers['etag'] = $headerToCache['etag'] = CacheHttp::makeEtag($arr);
				}
			}
			if($cache){
				$cache->close();
				$cache = null;
			}
			//网页和js的缓存要针对"pc、移动端、szmjapp"分别缓存
            $salt = '';
            if($page['pageandjs']){
                if(get_app_uid()){
                    $salt = 'szmjapp';
                }else{
                    $salt = strval(Http::isMobile());
                }
            }
			$cache = CacheHttp::create(TEMPDIR, $originalRemoteUrl->url, $headerToCache, $salt, $cacheSeconds, $page['cacheext']);
		}

		//客户端缓存机制：如果没写入缓存，除了网页外，如果尚未设置缓存，只要未禁止缓存，就启用1小时的客户端缓存
		if( DEBUGING<2 &&
			!$page['writecache'] &&
			(!isset($headers['pragma']) || strpos($headers['pragma'],'no-')===false) &&
		    (!isset($headers['cache-control']) || strpos($headers['cache-control'],'no-')===false) &&
		    (!isset($headers['expires']) || ($headers['expires']!='-1' && $headers['expires']!='0')) &&
			$http->getResponseStatusCode()==200 && strpos($_SERVER['HTTP_ACCEPT'],'text/html')===false &&
            empty($headers['cache-control'])
        ) {
            unset($headers['pragma'], $headers['expires']);
            $headers['cache-control'] = 'private, max-age=3600';
            $headers['last-modified'] = gmtDate(TIME);
            if(!$config['enable_cookie']){
                $headers['etag'] = CacheHttp::makeEtag(serialize($requestCookieCoding->remoteCookies).strval(Http::isMobile()).$page['cdn']);
            }
		}
	}

	//整理并输出HTTP头==

    //针对特定网站
    if(strpos($remoteUrl->url, 'szmj0.github.io')!==false || $remoteUrl->root=='shenzhouzhengdao.org'){
        //强制使用客户端缓存
        $headers['cache-control'] = 'private, max-age=31536000'; //设置private将允许浏览器缓存禁止cdn缓存
        if($is_behind_cdn){
            $headers['Edge-Control'] = 'no-store, bypass-cache'; //禁止cdn缓存
        }
        unset($headers['etag'], $headers['pragma'], $headers['expires']);
    }

	elseif(($page['ctype']=='html' || $page['ctype']=='xml' || $config['enable_cookie']) && (!empty($config['is_behind_cloudfront']) || !empty($config['is_behind_cloudflare']))){
		//如果网页在CF/cloudflare下，就禁止网页被过度缓存
        unset($headers['etag'], $headers['expires'], $headers['last-modified']);
        if($headers['cache-control']){
            $headers['cache-control'] = str_replace('public', 'private', $headers['cache-control']);
        }
        $headers['Edge-Control'] = 'no-store, bypass-cache';
	// }elseif($remoteUrl->root=='googlevideo.com' && $remoteUrl->script=='/videoplayback'){
    //     $headers['Timing-Allow-Origin'] = 'https://www.youtube.com';
    }

	//对需要更新的域从新赋值
	if($config['enable_cookie']){
		//加密cookie
		if(empty($headers['set-cookie'])){
			unset($headers['set-cookie']);
		}else{
			$responseCookieCoding = clone $requestCookieCoding;
			$responseCookieCoding->writeCookies($headers['set-cookie']);
			$headers['set-cookie']=$responseCookieCoding->setCookies;
			unset($responseCookieCoding);
		}
	}

	//保证另存为时可以正确获取到文件名
	if(!$page['supported'] && !empty($ext) && !isset($headers['content-disposition']) && $page['ctype']!='img' && strpos($requestUri,'?')!==false && ($filename=$http->getFilename())){
	    $filename = substr(md5($remoteUrl->url),0,8).fileext($filename);
	    $headers['content-disposition'] = (strpos($extlist['download'], $ext)!==false ? 'attachment' : 'inline') . "; filename={$filename}";
	}

	//其他需要更新或新增的响应头
	if($page['ctype']=='html' || $page['ctype']=='xml'){
		//补充charset
		if($page['charset'] && stripos($headers['content-type'], 'charset')===false){
			$headers['content-type']="{$headers['content-type']};charset={$page['charset']}";
		}
		//没有cookie[sessid]，就检查一下是否app
		if(empty($_COOKIE['sessid'])){
			get_app_uid();
		}
	}elseif(!$page['supported'] && $page['writecache'] && $page['cacheext'] && $cache){
		//对于以后直接返回资源缓存的url，其ETag和Last-Modified的值，本次从远端返回的与以后直接从本服务器返回的值不一样，所以要修改和去掉不一样的影响缓存的部分
		unset($headers['etag']);
		$headers['last-modified'] = gmtDate($cache->mtime);
	}
	$headers['x-cache'] = $cacheId ? 'HIT '.substr($cacheId,0,8) : 'MISS';

	//响应码
	if($cacheId){
		if(isset($headers['content-range'])){
			header('HTTP/1.1 206 Partial Content');
		}else{
			header('HTTP/1.1 200 OK');
		}
	}else{
	    $s = $http->getResponseStatusText();
	    if(substr($s,5,1)!='1'){
	        $s = preg_replace('#^HTTP/2(\.\d)?\s+#i', 'HTTP/1.1 ', $s);
	    }
	    header($s);
	}

	//如果是xml或媒体文件，就设置允许跨域
	if( in_array($page['ctype'],['xml','video','audio','media','embed','js']) ||
        strpos($extlist['all_media'], " $ext ")!==false ||
        isset($headers['access-control-allow-origin'])
    ){
        $headers['access-control-allow-origin']='*';
	}

	//输出响应头
	$keysCase = array('etag'=>'ETag');
	foreach($headers as $k=>$v){
		if($k && substr($k,0,2)!='__'){
			$k = isset($keysCase[$k]) ? $keysCase[$k] : ucwords($k, '-');
			if(is_array($v)){
				for($i=0; $i<count($v); $i++)
					header($k.': '.$v[$i], false);
			}else{
				header($k.': '.trim($v,' :'));
			}
		}
	}

	$page['responsed']=($http->getResponseStatusCode()!=404);

	//调试时使用
	//file_put_contents(TEMPDIR . '/cache_log.txt', ($cacheId?"<b>{$cacheId}</b>":'<i>MISS</i>') . " <a href='{$currentUrl->original}' target='_blank'>{$remoteUrl->url}</a>\n", FILE_APPEND);
}

/**
 * 返回每块儿HTTP主体时的事件
 * $finished=true 只表示与远端的http请求结束，不表示成功完成，需要在最底下的$result变量里判断是否成功完成
 */
function onReceivedBody($http, $data, $finished, $cacheId){
	global $config, $page, $remoteUrl, $urlCoding, $cache;
    static $totalBytes = 0;
    static $isTooBig = false;
    $isFirstBlock = $totalBytes==0;

    if(empty($data) && ($totalBytes==0 || !$finished)){
        return;
    }

	//去除网页代码之前的sxg头
	if($isFirstBlock && $page['istext'] && substr($data,0,3)=='sxg' && substr($data,7,1)=="\0" && preg_match('#^sxg\d-b\d#',$data)){
		$x = strpos($data, "\0\0\0\0\0\0@\0");
		if($x){
			$data = substr($data, $x+8);
		}else{
			$x = stripos($data, '<!DOCTYPE ');
			if($x>0 && $x<2000){
				$data = substr($data, $x);
			}
		}
        if(strlen($data)==0) return;
	}

	//根据文件内容开头几个字节判断是不是woff2字体文件，因为有的服务器会把此类文件返回为html格式，导致错误的后续处理
	if($isFirstBlock && $page['istext'] && substr($data,0,4)=='wOF2'){
	    header('Content-Type: font/woff2');
	    $page['istext'] = false;
	    $page['ctype'] = 'img';
    }

    //根据请求和响应内容判断是不是js或json格式，因为有的服务器会把此类文件返回为plain格式，导致错误的后续处理
    if(
        $isFirstBlock && $page['istext'] && strpos($http->contentType, 'text/plain')===0 &&
        preg_match('#^\s*(?:var \w+\s*=|\w+\(|\{|\[|\(function\(|function \w+\s*\()#',$data)
    ){
        header('Content-Type: text/javascript');
        $page['istext'] = true;
        $page['ctype'] = 'js';
    }

	//判断仅包含一个视频网址的ram
	if($isFirstBlock && substr($remoteUrl->file,-4)=='.ram' && preg_match('#^https?://[\w\-\./]+?\.(ra|rm|rmvb)\s*$#', $data)){
        $page['istext'] = true;
        $page['ctype'] = 'textram';
    }

	//判断文本型的asf列表
	if($isFirstBlock && $http->contentType=='video/x-ms-asf' && preg_match('#^\s*\[reference\][\r\n]#i', $data)){
        $page['istext'] = true;
        $page['ctype'] = 'textasf';
    }

	//判断文本型的m3u或m3u8列表
	if($isFirstBlock && substr($data,0,7)=='#EXTM3U'){
        $page['istext'] = true;
        $page['ctype'] = 'm3u8';
	}

    //判断manifest
    if($isFirstBlock && $page['istext'] && $page['ctype']=='js' && strpos($remoteUrl->file, 'manifest')!==false && in_array(substr(ltrim($data),0,1),['[','{']) && in_array(substr(rtrim($data),-1),[']','}'])){
        $page['ctype'] = 'manifest';
    }

    //如果css和js的内容像网页就作为网页处理，但要禁止被缓存
    if($isFirstBlock && in_array($page['ctype'],['css','js']) && preg_match('#^\s*<(?:\!DOCTYPE|html)#i',$data)) {
        $page['ctype'] = 'html';
        $page['writecache'] = false;
        if($cache){
            $cache->close();
            $cache = null;
        }
    }

    //判断谷歌/videoplayback
    if($remoteUrl->root=='googlevideo.com' && $remoteUrl->script=='/videoplayback' && $isFirstBlock){
        if($page['istext'] && preg_match('#^https://[\w\-]+\.googlevideo\.com/videoplayback\?[\w\-&%=\,\.]+$#', $data)){
            $url = $urlCoding->encodeUrl(trim($data),'video',null,true);
            header_remove('Content-Length');
            header_remove('Content-Type');
            header_remove('Content-Disposition');
            header_remove('Content-Range');
            header("Location: {$url}");
            exit;
        }elseif(preg_match('#https://[\w\-]+\.googlevideo\.com/videoplayback\?#', $data)){
            //响应里有未加密网址
            show_error(404, '', false, true);
        }
    }

    //判断是不是超过10M的大文件，禁止响应文本型大文件，禁止缓存所有大文件
    $totalBytes += strlen($data);
    if(!$isTooBig){
    	$isTooBig = $totalBytes > 15*1024*1024;
    }

	if($page['istext']){
        //禁止响应文本型大文件
        if($isTooBig){
            show_error(501, 'too big');
        }

		$page['data'].=$data;

        //文本类型需要下载完毕后再进行后续处理
		if($finished) {
			//如果是404页，就等到最后显示自定义的404页
			if($http->getResponseStatusCode()==404){
				$page['responsed']=false;
			}else{
				$page['responsed']=true;
				outputText($page['data'], true, $cacheId);
			}
		}elseif($http->lastError){
            show_error(504);
            $page['responsed']=false;
		}
	}else{
		//默认的缓冲区是4K，为了避免访客网速过慢，再在超时时间上增加10秒
		set_time_limit_ex($config['read_timeout']+10);

		//当识别为$isTooBig后，关闭缓存
		if($isTooBig && $cache){
            $cache->close();
            $cache=null;
		}

		//无需处理的类型直接输出，并保存到缓存里
		echo $data;

		if($cache){
			$cache->write($data);
		}
	}

	//完成缓存
	if($finished && $cache && !$http->lastError){
		$cache->finish();
		$cache = null;
	}
}

//输出编码后的网页
function outputText($data, $finish, $cacheId){
	global $config, $page, $currentUrl, $remoteUrl, $urlCoding, $bottom_navigation, $error_messages;
    global $start_time, $is_top_page, $cache, $isajax, $select_m3u8_resolution, $pwa;

	//网页处理超时（此值不宜太小，否则当处理大文档时可能会超时，比如大网页或大js）
	set_time_limit_ex(120);

	//记录三退提交成功的计数
    $goalJsCode = '';
	if($_SERVER['REQUEST_METHOD']=='POST' && $remoteUrl->script=='/post' && in_array($remoteUrl->host,['tuidang.epochtimes.com','santui.tuidang.org'])){
		$temp = mb_convert_encoding($data, APP_CHARSET, $page['charset']);
		if((strpos($temp,'您的声明已经提交到退党网站')!==false ||
		    strpos($temp,'请妥善保管此密码')!==false ||
		    strpos($temp,'查询声明是否发表')!==false ||
		    strpos($temp,'用查询密码查询')!==false)
		){
			$pass = '';
			if(isset($_POST['referer']) && $_POST['referer']=='nav'){
			    unset($_POST['referer']);
			    record_tui_data('底部导航条', $_SERVER['HTTP_REFERER'], $_POST, $temp, $pass);
			}else{
				record_tui_data('网页代理', $_SERVER['HTTP_REFERER'], $_POST, $temp, $pass);
			}
			record_counter('3tui');
			if($config['enable_matomo']){
			    require_once(APPDIR.'/include/matomo.inc.php');
                $goalJsCode = Matomo::getGoalJs($_POST['smnumber'],true).'</head>';
			}
		}
		unset($temp);
	}

	$htmlCoding=new HtmlCoding($currentUrl, $remoteUrl, $urlCoding, !empty($config['is_proxy_for_tui']) ? 'TUI' : 'PROXY');
    $htmlCoding->writecache=$page['writecache'];
    if(in_array($page['ctype'],['html','xml'])){
        if(!$page['charset']){
            $page['charset']=$htmlCoding->getCharset($data);
        }
        $htmlCoding->charset=$urlCoding->charset=$page['charset'];
        $htmlCoding->ctype=$page['ctype'];
    }

    //构造提前加密函数，响应sw重定向节点的要求
    $encodeTsFunc = null;
    if($page['ctype']=='m3u8' && !empty($_SERVER['HTTP_X_FORWARD_S']) && ($site=$pwa->getForwardSite())){
        $encodeTsFunc = function($url)use($remoteUrl, $site){
            if(substr($url,-3)=='.ts' && strpos($url,'?')===false){
                $url = $remoteUrl->getFullUrl($url);
                $url = encrypt_url_3nd($site, $url);
                return $url;
            }else{
                return null;
            }
        };
    }

	if(!$cacheId){
		//删除Unicode规范中的BOM字节序标记(UCS编码的 Big-Endian BOM, UCS编码的 Little-Endian BOM, UTF-8编码的BOM)
		if(ord($data[0])>=0xEF){
			if(substr($data,0,2)=="\xFE\xFF" || substr($data,0,2)=="\xFF\xFE"){
				$s = mb_convert_encoding($data, 'utf-8', 'UTF-16');
				if($s){
					$htmlCoding->charset = 'utf-8';
					$data = $s;
				}
			}elseif(substr($data,0,3)=="\xEF\xBB\xBF"){
				$data = substr($data, 3);
				$htmlCoding->charset = 'utf-8';
				if(substr($data,0,3)=="\xEF\xBB\xBF"){
					$data = substr($data, 3);
				}
			}
		}

		//链接本地化
		switch($page['ctype']){
            case 'css':
                //避免内容错误的css和js被缓存
                if($cache && preg_match('#^<(\!DOCTYPE|html)#',$data)) {
                    $page['writecache'] = false;
                    $cache->close();
                    $cache = null;
                }
			    $data=$htmlCoding->proxifyCss($data, true);
                //压缩空白字符
		        $data=$htmlCoding->compact($data, $page['ctype']);
                break;
            case 'js':
                //避免内容错误的css和js被缓存
                if($cache && preg_match('#^<(\!DOCTYPE|html)#',$data)) {
                    $page['writecache'] = false;
                    $cache->close();
                    $cache = null;
                }
			    $data=$htmlCoding->proxifyScript($data, true);
                //压缩空白字符
		        $data=$htmlCoding->compact($data, $page['ctype']);
                break;
            case 'manifest':
                $data=$htmlCoding->proxifyJson($data);
                break;
            case 'html':
            case 'xml':
                //如果网页超过2M，就删除其中的大小超过50K的base64形式的图片
                if(strlen($data)>2048000){
                    $data = preg_replace('#;base64,[\w\+/=]{50000,}(\\\\?["\'])#', ';base64,$1', $data);
                }
                //根据设置去除不支持的js和多媒体
                if(!$config['enable_script']) $data=$htmlCoding->stripScript($data);
                if(!$config['enable_media']) $data=$htmlCoding->stripMedia($data);
                //提取base标签里的链接地址
                $urlCoding->parseBaseUrl($data,true);
                //开始处理
			    $data=$htmlCoding->proxifyHtml($data, $page['ctype']);
                //压缩空白字符
		        $data=$htmlCoding->compact($data, $page['ctype']);
                break;
            case 'm3u8':
                $data=$htmlCoding->proxifyM3u8($data, $select_m3u8_resolution);
                break;
            case 'textasf':
                $data=$htmlCoding->proxifyAsf($data);
                break;
            case 'textram':
                $data=$htmlCoding->proxifyRam($data);
                break;
		}
		//保存到缓存
		if($finish && $page['writecache'] && $cache){
		    $cache->write($htmlCoding->cacheGetContentForCache($data));
        }
        //替换链接占位符
        $data=$htmlCoding->cacheReplaceLinks($data, null, $encodeTsFunc);
	}elseif($data){
	    //加密并替换缓存里的网址
	    $data=$htmlCoding->cacheReplaceLinkInCache($data, $encodeTsFunc);
	}

    //添加matomo转化代码，要避免这部分代码被上边的proxify处理
    if($goalJsCode){
        $data = str_replace_once('</head>', $goalJsCode, $data);
    }

	//替换域名占位变量
	$data = $htmlCoding->replaceVar($data, $page['cdn']);

	//还原地址栏里的地址，去掉备用域名插件所添加的尾巴
	if(!empty($config['player_only_allow_cn']) && empty($_COOKIE['__debug__']) && $page['ctype']=='html' && strpos($data, "/images/jwplayer.js") && !in_array(get_user_country(false),array('CN','LOCAL'))){
		$data = str_replace_once('</head>', '<script type="text/javascript">var _u_cn_="N",_r_url_="'.str_rot13($remoteUrl->url).'";</script></head>', $data);
	}

	//除了html和xml，其他类型文件的内容处理都在上边实现了，下边都是对网页类型文件的進一步处理

	//根据内容再次确定是不是网页类型
    $force_btmnv = false;
    $bodyEndPos = 0;
	if($page['ctype']=='html' && preg_match('#^\s*<#', $data)) {
        $bodyEndPos = strripos($data,'</body>');
        if($bodyEndPos===false) $bodyEndPos=0;
        //进一步判断是不是顶层的普通网页
        if($is_top_page && $bodyEndPos==0){
            $is_top_page = false;
        }
    }
    if(!$is_top_page){
        $force_btmnv = strpos($data, 'var force_btmnv=1')!==false;
    }

    //顶部地址栏、底部导航条和访问统计，顶部安全提示
    $jsCode = '';
    //底部导航条
    if($force_btmnv || ($is_top_page && $bodyEndPos>0 && $bottom_navigation['enable'])){
        $api_querystring = 'api=url&url=' . rawurlencode($currentUrl->url) . '&action=share';
        $api_querystring = juyuange_encrypt($api_querystring, DEFAULT_JYG_PASSWORD, true);
        $jsCode .= "var {$config['cookie_bottom_navigation']}_c='{$api_querystring}';";
        $url = encrypt_builtin_images_url('nav_' . (Http::isMobile()?'1':'0'), '.js') . (DEBUGING>0 ? '?_='.time() : '');
        $jsCode .= "append_js('{$url}'," . ($force_btmnv ? 'false' : 'true') . ");";
    }
    //顶部地址栏
    if($is_top_page && $bodyEndPos>0 && !empty($config['enable_address_bar'])) {
        $jsCode .= "append_js('/images/address.js',true);";
    }
    //针对大陆用户，在所有页面右下角显示“中秋神韵舞蹈技术技巧表演”小横幅
    if($is_top_page && $bodyEndPos>0 && $bottom_navigation['enable'] && $config['plugin']=='szzd'){
        // fltad_conf 的原始内容为：
        /*
        [
            'title' => '2024年神韵中秋节联欢会技术表演',
            'image' => 'https://image1-us-west.cloudokyo.cloud/image/v1/d9/1a/66/d91a6650-af8e-4b11-824b-1e54cf5ee95c/672.webp',
            'text' => '神韵的艺术家和见习演员70多人展示了令人叹为观止的中国古典舞技巧，各种高难度的翻腾，演员们做得轻盈而稳健。',
            'url' => '/CG3of',
            'mp4url' => '/CG3of.mp4',
            'mp4text' => '下载高清MP4',
            'move' => 0
        ]
        */
        //转换后内容
        /*
        $mp4url = ''; // add_url_hash('/CG3of.mp4', true);
        $url = "/?{$config['built_in_name']}=" . encrypt_builtin("get_country");
        $jsCode .= 'if(fltad){$z.get("' . $url . '", function(c){
            if(c==="CN" || c==="LOCAL" || !!' . DEBUGING . '){
                fltad({"title":"2024\u5e74\u795e\u97f5\u4e2d\u79cb\u8282\u8054\u6b22\u4f1a\u6280\u672f\u8868\u6f14","image":"https:\/\/image1-us-west.cloudokyo.cloud\/image\/v1\/d9\/1a\/66\/d91a6650-af8e-4b11-824b-1e54cf5ee95c\/672.webp","text":"\u795e\u97f5\u7684\u827a\u672f\u5bb6\u548c\u89c1\u4e60\u6f14\u545870\u591a\u4eba\u5c55\u793a\u4e86\u4ee4\u4eba\u53f9\u4e3a\u89c2\u6b62\u7684\u4e2d\u56fd\u53e4\u5178\u821e\u6280\u5de7\uff0c\u5404\u79cd\u9ad8\u96be\u5ea6\u7684\u7ffb\u817e\uff0c\u6f14\u5458\u4eec\u505a\u5f97\u8f7b\u76c8\u800c\u7a33\u5065\u3002","url":"\/CG3of","mp4url":"' . $mp4url . '","mp4text":"\u4e0b\u8f7d\u9ad8\u6e05MP4","move":0});
            }
        })}';
        */
    }

    /*
    访问统计
    如果有上次访问时间就是回头客
    在浏览网页时，如果是新客就在浏览器端设置cookie（u+key+6位时间），然后在tj文件里检查这个cookie，用cookie避免重复探测tj导致访问量虚高
    如果js检测到新客cookie，就设置为访问时间，并计入访问统计
    但是此方案还解决不了以基于浏览器的技术探测网页所导致的访问量虚高
    */
    if($is_top_page && $bodyEndPos>0){
		$cookieName13 = str_rot13($config['cookie_counter']);
		$cookieKey13 = str_rot13(md5_16(php_uname().$currentUrl->host.$_SERVER['HTTP_USER_AGENT']));
		$builtinName13 = str_rot13($config['built_in_name']);
		$builtinValue13 = str_rot13(encrypt_builtin('tj'));
		$jsCode .= "countv('{$cookieName13}', '{$cookieKey13}', '{$builtinName13}', '{$builtinValue13}');";
    }
    //组合
    if($jsCode){
        $jsCode = "<script type='text/javascript'>{$jsCode}</script>";
    }
    //首次访问时在网页顶部显示安全提示
    if($is_top_page && $bodyEndPos>0 && !get_app_uid() && !empty($config['top_tips'])){
        $jsCode.=get_tipsdlg();
    }
    if($jsCode){
		$data=substr_replace($data,$jsCode,$bodyEndPos,0);
    }

    //把被阻止的链接标记上特殊的样式，以方便用户识别是不能点击的
    if($is_top_page && strpos($data,"/blank/")>0){
        $data = str_replace_once('</head>', "<style type='text/css'>a[href*='/blank/']{color:#999 !important;font-weight:normal !important;text-decoration:line-through !important;}</style></head>", $data);
    }

	//处理远端网址里的hash
	if($bodyEndPos>0 && $remoteUrl->fragment && !$page['isajax']){
		$data.="<script type='text/javascript'>location.hash='{$remoteUrl->fragment}';</script>";
	}

	//添加第三方统计代码
	if($is_top_page && !empty($config['analytics'])){
		$data.=$config['analytics'];
	}

	//记录快捷网址的访问记录
	if(isset($_SERVER['REQUEST_ADDRESS_ID'])){
		$s = $urlCoding->getAddressOf($_SERVER['REQUEST_ADDRESS_ID']);
		$x = strpos($s,'#');
		if($x>0) {
			$s=substr($s,0,$x);
		}
		if($s==$remoteUrl->url || "{$s}/"==$remoteUrl->url){
			file_put_contents(DATADIR . '/~counter_visit_address_temp.dat', date('Ymd').",{$_SERVER['REQUEST_ADDRESS_ID']}\n", FILE_APPEND);
		}
	}

	//如果不是蜘蛛，就需要加密内容：
	//1.xml页面简单编码汉字，因为如果用javascript方式加密会破坏原有格式
	//2.手机访问html时只简单编码汉字，因为有些手机不支持javascript脚本
	//3.普通浏览器浏览html页面时采用javascript进行加密
	$doneEncryptHtml = false;
	if($page['ctype']) {
		if($page['ctype']=='js' && DEBUGING<2){
			$data=$htmlCoding->encodeHanzi($data, $page['charset'], $page['ctype'], 'no');
			$data=htmlentities_to_js($data);
		}elseif($page['ctype']=='xml'){
			$data=$htmlCoding->encodeHanzi($data, $page['charset'], $page['ctype'], 'no');
		}elseif($page['ctype']=='html' && (DEBUGING==2 || $isajax || !empty($_SERVER['REQUEST_HOOKAJAX_TYPE']) /* || (!$page['isframe'] && !$is_top_page) */ )){
		    $data=$htmlCoding->encodeHanzi($data, $page['charset'], $page['ctype'], !$isajax && empty($_SERVER['REQUEST_HOOKAJAX_TYPE']) ? 'auto' : 'no');
            //在页尾显示错误信息
            if($error_messages){
                $data .= "/* <div style='padding:10px; margin:10px; border:1px solid #FFB2B6; background-color:#FFE8E7; color:#333; font-size:12px; clear:both; text-align:left;'><pre>".trim($error_messages)."</pre></div> */";
            }
            //在页尾显示页面执行时间
            if(DEBUGING>2){
                $data .= "/* <div style='clear:both;'>page size: " . round(strlen($data)/1024,2) . "kb, load time: " . round(microtime(true)-$start_time,3) . "s</div> */";
            }
		}elseif($page['ctype']=='html'){
		    $doneEncryptHtml = true;
			$data=$htmlCoding->encryptHtml($data, $page['charset']);
		}
	}

	//网页输出超时（按照1KB/秒的速度再增加30秒计算）
	set_time_limit_ex(strlen($data)/1024 + 30);

	//对HOOKAJAX的内容進行编码
	if(!empty($_SERVER['REQUEST_HOOKAJAX_TYPE'])){
		$data = hookajax_encode($_SERVER['REQUEST_HOOKAJAX_TYPE'], $data);
	}

	//压缩
	switch ($config['zlib_output']){
		case 0:
			//不支持压缩（指定原始长度）
			header('Content-Length: '.strlen($data));
			echo $data;
			break;
		case 1:
			//自动压缩（不指定原始长度或压缩后的长度，系统会自动设置的）
            header_remove("Content-Length");
			header('Content-Encoding: gzip');
			header('Vary: Accept-Encoding');
			echo $data;
			break;
		case 2:
            //手动压缩（指定压缩后的长度）
            if($doneEncryptHtml){
                //如果网页已经加密，由于已经在加密过程中压缩了或者加密后的密文的压缩率很低，所以为了考虑性能就不重复压缩了
            }else{
            	$data .= @ob_get_clean();
            	$data = gzencode($data,6);
            	header('Content-Encoding: gzip');
            	header('Vary: Accept-Encoding');
            }
            header('Content-Length: '.strlen($data));
            echo $data;
            break;
	}
}

//下边这个代码，是为了保证网页结束时清除资源
function on_shutdown(){
	global $http, $cache;
	if($http) {
		$http->close(true);
		$http=null;
	}
	if($cache){
		$cache->close();
		$cache=null;
	}
	if(function_exists('error_get_last')){
		$e = error_get_last();
		if($e){
			myErrorHandler($e['type'], $e['message'], $e['file'], $e['line']);
		}
	}
}
if(function_exists('register_shutdown_function')) register_shutdown_function('on_shutdown');

// ================================================================================================
// 从远端或缓存读取网页等资源
// ================================================================================================

$http = Http::create($config);
if($http===false){
	echo '<p>服务器配置有误，请联系管理员！</p>';
	exit;
}
$http->proxy=$config['proxy'];
$http->currentHome=$currentUrl->home;
$http->redirect = (!$redirect_original) && $page['ctype'] && $page['ctype']!='html';

//针对特定网站设置请求头或表单数据
if(in_array($remoteUrl->root, ['googlevideo.com','youtube.com','ytimg.com'])){
    $ytbHome = Http::isMobile() ? 'https://m.youtube.com' : 'https://www.youtube.com';
    switch($remoteUrl->root){
        case 'googlevideo.com':
            $remoteReferer = $ytbHome . '/';
            $http->setRequestHeader('Origin', $ytbHome);
            if(isset($_SERVER['HTTP_SEC_FETCH_SITE'])){
                $http->setRequestHeader('Sec-Fetch-Site', 'cross-site');
            }
            break;
        case 'youtube.com':
            //修改请求头
            if($remoteReferer && strpos($remoteReferer, '.youtube.com/watch?')!==false){
                //保持播放页的完整referer
            }else{
                //其它网页值保留首页
                $remoteReferer = $ytbHome . '/';
            }
            if(isset($_SERVER['HTTP_SEC_FETCH_SITE'])){
                $http->setRequestHeader('Sec-Fetch-Site', 'same-origin');
            }
            break;
        case 'ytimg.com':
            $remoteReferer = '';
            break;
    }
}else{
    //默认使用首页作为referer
    if(!$remoteReferer) $remoteReferer = $remoteUrl->home;
}

$http->setRequestHeader('Referer', $remoteReferer);
$http->setAuth($requestCookieCoding->remoteAuth);
if($config['enable_cookie']){
	foreach($requestCookieCoding->remoteCookies as $k=>$v){
		$http->setCookie($k, $v);
	}
}
if(isset($_SERVER['HTTP_RANGE'])){
	$http->setRequestHeader('Range', $_SERVER['HTTP_RANGE']);
}
//自定义请求头
if(!empty($config['additional_http_headers'])){
    foreach($config['additional_http_headers'] as $k=>$v){
	    $http->setRequestHeader(trim($k), trim($v));
    }
}
//覆盖useragent
if($new_useragent){
	$http->setRequestHeader('user-agent', $new_useragent);
}

//设置要提交的表单数据
if(!empty($_POST)){
	//解密POST数据
	if(isset($_POST['fk_charset'])){
		$fk_charset=strtoupper($_POST['fk_charset']);
		unset($_POST['fk_charset']);
	}else{
		$fk_charset=null;
	}
	foreach($_POST as $k=>$v){
		if(str_decrypt_form($k,$v,$fk_charset)){
			unset($_POST[$k]);
			$_POST[substr($k,3)]=$v;
		}
		unset($v);
	}
	foreach($_POST as $k=>$v){
		$http->addPostField($k, $v);
	}
}
//设置要提交的其他类型数据
elseif(!empty($_SERVER['CONTENT_LENGTH'])){
    if(empty($php_input_data)){
        $php_input_data = file_get_contents('php://input');
    }
	if(!empty($php_input_data)){
	    $http->setPostData($php_input_data);
    }
}

//设置上传数据
if(!empty($_FILES)){
	foreach($_FILES as $k=>$v){
		$filename=isset($v['name'])?$v['name']:$v['tmp_name'];
		$content=null;
		if(!empty($v['tmp_name']) && is_string($v['tmp_name']) && is_uploaded_file($v['tmp_name'])){
			$content=@file_get_contents($v['tmp_name']);
			unlink($v['tmp_name']);
		}
		if($filename && isset($content[0]))
			$http->addPostFile($k, $filename, $content);
	}
}

//是否读取缓存以及缓存的设置
$http->readCache = $page['readcache'] && !isset($_COOKIE['_no_cache_']);
    /*
    (
        $page['readcache'] && ($page['ctype']=='js' || $page['ctype']=='css') && !isset($_COOKIE['_no_cache_'])
    ) ||
    (
        $page['readcache'] &&
        (!DEBUGING || !isset($_SERVER['HTTP_CACHE_CONTROL']) || $_SERVER['HTTP_CACHE_CONTROL']!='no-cache') &&
        (!DEBUGING || !isset($_SERVER['HTTP_PRAGMA']) || $_SERVER['HTTP_PRAGMA']!='no-cache')
    );
    */
$http->cacheDir = TEMPDIR;
$http->cacheExt = $page['cacheext'];
$http->cacheVer = APP_VER;

//有些网站的缓存有效期比较特殊，需要单独设置
if($http->readCache && $page['ctype']=='html' && $remoteUrl->root=='youtube.com'){
	$http->cacheExpire = TIME+3600*4; //因为视频真实地址的有效期是5小时多
}

//发出请求
set_time_limit_ex($config['connect_timeout']+5);
switch ($_SERVER['REQUEST_METHOD']){
	case 'HEAD':
		$headers = $http->head($remoteUrl, null);
		if($headers){
		    $result = $http->getResponseStatusCode();
		}else{
		    $result = $http->lastError;
		}
		break;
	case 'GET':
		$keys=array_keys($address);
		$current_id=isset($address[0])?0:$keys[0];
		do{
			$http->maxRetry = $current_id==0 ? 2 : 1;
			$result = $http->get($remoteUrl, null, null, 'onReceivedHeader', 'onReceivedBody');
			$current_id++;
		}while(!$result && $http->lastError=='internet' && empty($_GET) && isset($address[$current_id]) && ($remoteUrl=Url::create($urlCoding->getAddressOf($current_id))));
		break;
	case 'POST':
		$result = $http->post($remoteUrl, null, null, null, 'onReceivedHeader', 'onReceivedBody');
		break;
	default:
		$http->lastError = 501;
		break;
}

//把不完整的网页内容也输出吧，但是要避免被缓存
if(!$result && !$page['responsed'] && $page['data']){
    header('Cache-Control: no-cache, must-revalidate');
    header('Pragma: no-cache');
	outputText($page['data'], false, false);
}
if($cache) {
	$cache->close();
	$cache=null;
}

$lastError=$http->lastError;
$contentLength=$http->contentLength;
$http->close();
unset($http);

//判断结果
if(!$result && !$page['responsed']){
	switch ($lastError){
		case 204:
		case 206:
		case 'partial':
			//只从远端接收到部分数据，但是也不排除是因为服务器返回的Content-Length错误而引起，所以，遇到此问题只显示，而不做缓存。
			break;
		case 400:
			show_error(400);
		case 403:
            if($error_message_403){
                $error_message_403 .= '<br><br>';
                $homeUrl = $urlCoding->encodeUrl($remoteUrl->home, null, null, true);
                if($remoteReferer != $remoteUrl->home) {
                    $url = $urlCoding->encodeUrl($remoteReferer, null, null, true);
                    $error_message_403 .= "<a href='{$url}'>返回上一页</a> &nbsp; <a href='{$homeUrl}'>返回首页</a>";
                }else{
                    $error_message_403 .= "<a href='{$homeUrl}'>返回首页</a>";
                }
            }
            if($remoteUrl->script=='/' && in_array($remoteUrl->host,['www.tuidang.org','santui.tuidang.org'])){
                //如果被退党网的antispam机制拦截，为了保证继续浏览，转向到大纪元退党网
                $url = $urlCoding->encodeUrl('http://tuidang.epochtimes.com/', null, null, true);
                header("Location: {$url}");
                exit;
            }elseif($error_message_403){
                $page['ctype'] = $ctype = 'html';
                remove_headers();
                header('HTTP/1.1 OK');
                header('Content-Type: text/html;charset='.APP_CHARSET);
                outputText(get_fullpage('', $error_message_403), true, null);
                exit;
            }else{
                show_error(403, $error_message_403, true);
            }
		case 404:
		case 'missing':
			if($is_top_page && file_exists(APPDIR.'/404.htm')){
				header('HTTP/1.1 404 Not Found');
                header('Access-Control-Allow-Origin: *');
				header('Content-Type: text/html; charset='.APP_CHARSET);
				$html=file_get_contents(APPDIR.'/404.htm');
				$html=str_replace('{apppath}', $currentUrl->home.$currentUrl->path, $html);
				//导航
				$links = array();
				foreach($address as $v){
					$arr = explode('|',$v,2);
					if(count($arr)==2 && $arr[0] && $arr[1]){
						$arr[1]=$currentUrl->getFullUrl(trim($arr[1]," \t*"));
						$link = "<li><a href='{$arr[1]}' target='_blank'>{$arr[0]}</a></li>";
						if(!in_array($link, $links)) $links[]= $link;
					}
				}
				$links = implode('', $links);
				$htmlCoding=new HtmlCoding($currentUrl, $remoteUrl, $urlCoding, null);
				$links=$htmlCoding->proxifyHtml($links);
				$links=str_replace(array('{app_site}','{apppath}'), $currentUrl->home.$currentUrl->path, $links);
				$links=$htmlCoding->encryptHtml($links,APP_CHARSET);
				$html=str_replace('{link}', $links, $html);
				exit($html);
			}else{
                show_error(404);
			}
		case 500:
		case 501:
		case 502:
		case 503:
		case 504:
		case 505:
		    if(empty($page['data'])) show_error($lastError);
		    break;
		case 'internet':
			show_error(504, 'Remote server not exists or timeout', false, true);
		case 'timeout':
			show_error(504, 'timeout', false, true);
		case 'resource':
			header('HTTP/1.1 403 Forbidden');
		    show_error(403, "禁止下载超过 {$config['max_file_size']}MB 的文件");
		case 'cancel':
			exit;
		default:
		    if($isframe){
				exit($lastError);
		    }elseif($lastError == '52. Empty reply from server'){
		        header('HTTP/1.1 504 Empty reply from server');
		    }elseif($page['ctype']=='js' || strpos($extlist['jscss']," $ext ")!==false){
			    header('HTTP/1.1 505 Server Error');
			}else{
				echo $lastError;
			}
			exit;
	}
}
