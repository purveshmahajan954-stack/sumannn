<?php
/**
 * Suman Unique Collection - Store API
 * Standard PHP backend (cPanel / shared hosting compatible).
 */

header('Content-Type: application/json');
header('Cache-Control: no-store');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Headers: authorization, content-type, x-requested-with');
header('Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'OPTIONS') { http_response_code(204); exit; }

define('SB_URL', 'https://vluixodicoyjuofoqkwj.supabase.co');
define('SB_KEY', 'sb_secret_EUKOUzNs3e1PoXTtUB1H9Q_2lUG0vz3');
define('JWT_SECRET', 'suman-unique-collection-jwt-2026-8f3b91c4e7a25d60');

/* ---------------- helpers ---------------- */

function out($data, $status = 200) {
    http_response_code($status);
    echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

function http_req($url, $method = 'GET', $headers = [], $body = null) {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CUSTOMREQUEST  => $method,
        CURLOPT_HTTPHEADER     => $headers,
        CURLOPT_TIMEOUT        => 30,
    ]);
    if ($body !== null) curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
    $res  = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    return [$code, $res === false ? '' : $res];
}

function rest($path, $method = 'GET', $body = null, $prefer = null) {
    $headers = ['apikey: ' . SB_KEY, 'Content-Type: application/json'];
    if ($prefer) $headers[] = 'Prefer: ' . $prefer;
    list($code, $text) = http_req(SB_URL . '/rest/v1/' . $path, $method, $headers,
        $body === null ? null : json_encode($body, JSON_UNESCAPED_SLASHES));
    if ($code < 200 || $code >= 300) out(['error' => $text ?: "Request failed ($code)"], 500);
    return $text === '' ? null : json_decode($text, true);
}

function db_select($table, $query = '') { return rest($table . '?' . $query) ?: []; }
function db_insert($table, $body)       { return rest($table, 'POST', $body, 'return=representation') ?: []; }
function db_update($table, $q, $body)   { return rest($table . '?' . $q, 'PATCH', $body, 'return=representation') ?: []; }
function db_upsert($table, $body, $oc)  { return rest($table . '?on_conflict=' . $oc, 'POST', $body, 'resolution=merge-duplicates,return=representation') ?: []; }
function db_remove($table, $q)          { return rest($table . '?' . $q, 'DELETE'); }

function first($rows) { return (is_array($rows) && count($rows)) ? $rows[0] : null; }

function b64url($bin) { return rtrim(strtr(base64_encode($bin), '+/', '-_'), '='); }
function b64url_decode($s) { return base64_decode(strtr($s, '-_', '+/') . str_repeat('=', (4 - strlen($s) % 4) % 4)); }

function sign_token($payload, $days = 30) {
    $payload['iat'] = time();
    $payload['exp'] = time() + $days * 86400;
    $head = b64url(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
    $data = $head . '.' . b64url(json_encode($payload));
    return $data . '.' . b64url(hash_hmac('sha256', $data, JWT_SECRET, true));
}

function verify_token($token) {
    if (!$token) return null;
    $parts = explode('.', $token);
    if (count($parts) !== 3) return null;
    $expect = b64url(hash_hmac('sha256', $parts[0] . '.' . $parts[1], JWT_SECRET, true));
    if (!hash_equals($expect, $parts[2])) return null;
    $payload = json_decode(b64url_decode($parts[1]), true);
    if (!is_array($payload)) return null;
    if (isset($payload['exp']) && $payload['exp'] < time()) return null;
    return $payload;
}

function verify_password($password, $stored) {
    if (!$stored) return false;
    $p = explode('$', $stored);
    if (count($p) < 3) return false;
    $salt = base64_decode($p[1]);
    $hash = base64_encode(hash_pbkdf2('sha256', $password, $salt, 100000, 32, true));
    return hash_equals($p[2], $hash);
}

function bearer() {
    $h = '';
    if (isset($_SERVER['HTTP_AUTHORIZATION'])) $h = $_SERVER['HTTP_AUTHORIZATION'];
    elseif (isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) $h = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
    elseif (function_exists('apache_request_headers')) {
        foreach (apache_request_headers() as $k => $v) if (strtolower($k) === 'authorization') $h = $v;
    }
    if (!$h) return null;
    return preg_replace('/^Bearer\s+/i', '', trim($h));
}

function auth_user($token) {
    if (!$token || count(explode('.', $token)) !== 3) return null;
    list($code, $res) = http_req(SB_URL . '/auth/v1/user', 'GET',
        ['apikey: ' . SB_KEY, 'Authorization: Bearer ' . $token]);
    if ($code < 200 || $code >= 300) return null;
    return json_decode($res, true);
}

function password_sign_in($email, $password) {
    list($code, $res) = http_req(SB_URL . '/auth/v1/token?grant_type=password', 'POST',
        ['apikey: ' . SB_KEY, 'Content-Type: application/json'],
        json_encode(['email' => $email, 'password' => $password]));
    if ($code < 200 || $code >= 300) return null;
    return json_decode($res, true);
}

function create_auth_user($email, $password, $metadata = []) {
    list($code, $res) = http_req(SB_URL . '/auth/v1/admin/users', 'POST',
        ['apikey: ' . SB_KEY, 'Authorization: Bearer ' . SB_KEY, 'Content-Type: application/json'],
        json_encode(['email' => $email, 'password' => $password, 'email_confirm' => true, 'user_metadata' => $metadata]));
    $data = json_decode($res, true);
    if ($code < 200 || $code >= 300) return ['error' => $data['msg'] ?? $data['message'] ?? 'Could not create the account.'];
    return $data;
}

function strip_null($arr) {
    $o = [];
    foreach ($arr as $k => $v) if ($v !== null) $o[$k] = $v;
    return $o;
}

function ensure_profile($authUser, $extras = []) {
    $email = strtolower((string)($authUser['email'] ?? ''));
    $row = first(db_select('users', 'auth_user_id=eq.' . $authUser['id'] . '&select=*&limit=1'));
    if (!$row && $email) {
        $row = first(db_select('users', 'email=eq.' . rawurlencode($email) . '&select=*&limit=1'));
        if ($row) $row = first(db_update('users', 'id=eq.' . $row['id'], ['auth_user_id' => $authUser['id']]));
    }
    $meta = $authUser['user_metadata'] ?? [];
    if (!$row) {
        return first(db_insert('users', [
            'auth_user_id'  => $authUser['id'],
            'name'          => $extras['name'] ?? $meta['full_name'] ?? $meta['name'] ?? explode('@', $email)[0],
            'email'         => $email,
            'phone'         => $extras['phone'] ?? $meta['phone'] ?? null,
            'date_of_birth' => $extras['date_of_birth'] ?? $meta['date_of_birth'] ?? null,
            'gender'        => $extras['gender'] ?? $meta['gender'] ?? null,
            'role'          => 'user',
            'status'        => 'active',
        ]));
    }
    $patch = strip_null([
        'name'          => empty($row['name'])          ? ($extras['name'] ?? $meta['full_name'] ?? $meta['name'] ?? null) : null,
        'phone'         => empty($row['phone'])         ? ($extras['phone'] ?? $meta['phone'] ?? null) : null,
        'date_of_birth' => empty($row['date_of_birth']) ? ($extras['date_of_birth'] ?? $meta['date_of_birth'] ?? null) : null,
        'gender'        => empty($row['gender'])        ? ($extras['gender'] ?? $meta['gender'] ?? null) : null,
    ]);
    if (count($patch)) {
        $patch['updated_at'] = gmdate('c');
        $row = first(db_update('users', 'id=eq.' . $row['id'], $patch));
    }
    return $row;
}

function current_user_row() {
    $token = bearer();
    $au = auth_user($token);
    if ($au) {
        $p = ensure_profile($au);
        if (!$p || ($p['status'] ?? '') === 'blocked') return null;
        return $p;
    }
    $payload = verify_token($token);
    if (!$payload || empty($payload['sub'])) return null;
    $row = first(db_select('users', 'id=eq.' . $payload['sub'] . '&select=*&limit=1'));
    if (!$row || ($row['status'] ?? '') === 'blocked') return null;
    return $row;
}

function admin_user_row() {
    $token = bearer();
    $u = auth_user($token);
    if ($u) {
        $role = $u['app_metadata']['role'] ?? $u['user_metadata']['role'] ?? null;
        $isAdmin = $role === 'admin';
        if (!$isAdmin) {
            $rows = db_select('admin_profiles', 'user_id=eq.' . $u['id'] . '&role=eq.admin&select=id&limit=1');
            $isAdmin = count($rows) > 0;
        }
        if (!$isAdmin) return null;
        return [
            'id'         => $u['id'],
            'name'       => $u['user_metadata']['name'] ?? 'Administrator',
            'email'      => $u['email'] ?? null,
            'phone'      => $u['phone'] ?? null,
            'role'       => 'admin',
            'created_at' => $u['created_at'] ?? null,
        ];
    }
    $payload = verify_token($token);
    if (!$payload || empty($payload['sub'])) return null;
    $legacy = first(db_select('users', 'id=eq.' . $payload['sub'] . '&select=*&limit=1'));
    return ($legacy && ($legacy['role'] ?? '') === 'admin') ? $legacy : null;
}

/* ---------------- shapers ---------------- */

function public_user($u) {
    return ['_id' => $u['id'], 'name' => $u['name'] ?? null, 'email' => $u['email'] ?? null,
            'phone' => $u['phone'] ?? null, 'role' => $u['role'] ?? null, 'createdAt' => $u['created_at'] ?? null];
}
function public_customer($u) {
    return ['_id' => $u['id'], 'id' => $u['id'], 'authUserId' => $u['auth_user_id'] ?? null,
            'fullName' => $u['name'] ?? null, 'name' => $u['name'] ?? null, 'email' => $u['email'] ?? null,
            'phone' => $u['phone'] ?? null, 'dateOfBirth' => $u['date_of_birth'] ?? null,
            'gender' => $u['gender'] ?? null, 'status' => $u['status'] ?? 'active',
            'createdAt' => $u['created_at'] ?? null, 'updatedAt' => $u['updated_at'] ?? null];
}
function customer_columns($b) {
    $c = [];
    if (isset($b['fullName']) || isset($b['name'])) $c['name'] = $b['fullName'] ?? $b['name'];
    if (isset($b['phone']) || isset($b['mobile']))  $c['phone'] = $b['phone'] ?? $b['mobile'];
    if (array_key_exists('dateOfBirth', $b)) $c['date_of_birth'] = $b['dateOfBirth'] === '' ? null : $b['dateOfBirth'];
    if (array_key_exists('gender', $b))      $c['gender'] = $b['gender'] === '' ? null : $b['gender'];
    $c['updated_at'] = gmdate('c');
    return $c;
}
function public_product($p) {
    return [
        '_id' => $p['id'] ?? null, 'name' => $p['name'] ?? null, 'slug' => $p['slug'] ?? null,
        'category' => $p['category'] ?? null, 'categoryId' => $p['category_id'] ?? null,
        'subcategory' => $p['subcategory'] ?? null, 'size' => $p['size'] ?? null,
        'price' => (float)($p['price'] ?? 0),
        'discountPrice' => isset($p['discount_price']) && $p['discount_price'] !== null ? (float)$p['discount_price'] : null,
        'image' => $p['image'] ?? null, 'images' => $p['images'] ?? [], 'stock' => $p['stock'] ?? 0,
        'status' => $p['status'] ?? 'active', 'sku' => $p['sku'] ?? null,
        'description' => $p['description'] ?? null, 'fabric' => $p['fabric'] ?? null,
        'workDetails' => $p['work_details'] ?? null, 'bottomDetails' => $p['bottom_details'] ?? null,
        'dupattaDetails' => $p['dupatta_details'] ?? null, 'colors' => $p['colors'] ?? [],
        'sizes' => $p['sizes'] ?? [], 'overview' => $p['overview'] ?? null,
        'sizeFit' => $p['size_fit'] ?? null, 'material' => $p['material'] ?? null,
        'careGuide' => $p['care_guide'] ?? null, 'shippingRefund' => $p['shipping_refund'] ?? null,
        'isBestseller' => !empty($p['is_bestseller']),
        'createdAt' => $p['created_at'] ?? null, 'updatedAt' => $p['updated_at'] ?? null,
    ];
}
function arr_field($v) {
    if ($v === null) return null;
    if (is_array($v)) return array_values(array_filter($v));
    return array_values(array_filter(array_map('trim', explode(',', (string)$v))));
}
function product_columns($b) {
    $c = [];
    $map = ['name'=>'name','slug'=>'slug','category'=>'category','categoryId'=>'category_id','subcategory'=>'subcategory',
            'size'=>'size','image'=>'image','images'=>'images','status'=>'status','sku'=>'sku','description'=>'description',
            'fabric'=>'fabric','workDetails'=>'work_details','bottomDetails'=>'bottom_details','dupattaDetails'=>'dupatta_details',
            'sizeFit'=>'size_fit','careGuide'=>'care_guide','shippingRefund'=>'shipping_refund','isBestseller'=>'is_bestseller'];
    foreach ($map as $in => $col) if (array_key_exists($in, $b)) $c[$col] = $b[$in];
    if (array_key_exists('price', $b))         $c['price'] = (float)$b['price'];
    if (array_key_exists('discountPrice', $b)) $c['discount_price'] = $b['discountPrice'] === null || $b['discountPrice'] === '' ? null : (float)$b['discountPrice'];
    if (array_key_exists('stock', $b))         $c['stock'] = (int)$b['stock'];
    if (array_key_exists('colors', $b))        $c['colors'] = arr_field($b['colors']);
    if (array_key_exists('sizes', $b))         $c['sizes'] = arr_field($b['sizes']);
    if (array_key_exists('overview', $b) || array_key_exists('description', $b)) $c['overview'] = $b['overview'] ?? $b['description'];
    if (array_key_exists('material', $b) || array_key_exists('fabric', $b))      $c['material'] = $b['material'] ?? $b['fabric'];
    $c['updated_at'] = gmdate('c');
    return $c;
}
function public_category($c) {
    return ['_id' => $c['id'], 'id' => $c['id'], 'name' => $c['name'] ?? null, 'slug' => $c['slug'] ?? null,
            'description' => $c['description'] ?? null, 'image' => $c['image_url'] ?? null,
            'imageUrl' => $c['image_url'] ?? null, 'status' => $c['status'] ?? null,
            'sortOrder' => $c['sort_order'] ?? null, 'createdAt' => $c['created_at'] ?? null];
}
function category_columns($b) {
    $c = [];
    if (array_key_exists('name', $b)) $c['name'] = $b['name'];
    if (array_key_exists('slug', $b) && $b['slug']) $c['slug'] = $b['slug'];
    elseif (!empty($b['name'])) $c['slug'] = trim(preg_replace('/[^a-z0-9]+/', '-', str_replace('&', 'and', strtolower($b['name']))), '-');
    if (array_key_exists('description', $b)) $c['description'] = $b['description'];
    if (array_key_exists('imageUrl', $b) || array_key_exists('image', $b)) $c['image_url'] = $b['imageUrl'] ?? $b['image'];
    if (array_key_exists('status', $b)) $c['status'] = $b['status'];
    if (array_key_exists('sortOrder', $b)) $c['sort_order'] = (int)$b['sortOrder'];
    $c['updated_at'] = gmdate('c');
    return $c;
}
function public_product_image($i) {
    return ['_id' => $i['id'], 'id' => $i['id'], 'productId' => $i['product_id'],
            'url' => $i['image_url'], 'isPrimary' => !empty($i['is_primary']), 'sortOrder' => $i['sort_order'] ?? 0];
}
function public_address($a) {
    return ['_id' => $a['id'], 'fullName' => $a['full_name'] ?? null, 'mobile' => $a['mobile'] ?? null,
            'alternateMobile' => $a['alternate_mobile'] ?? null, 'houseNo' => $a['house_no'] ?? null,
            'street' => $a['street'] ?? null, 'landmark' => $a['landmark'] ?? null, 'city' => $a['city'] ?? null,
            'state' => $a['state'] ?? null, 'country' => $a['country'] ?? null, 'pincode' => $a['pincode'] ?? null,
            'addressType' => $a['address_type'] ?? null, 'isDefault' => !empty($a['is_default'])];
}
function address_columns($b) {
    $map = ['fullName'=>'full_name','mobile'=>'mobile','alternateMobile'=>'alternate_mobile','houseNo'=>'house_no',
            'street'=>'street','landmark'=>'landmark','city'=>'city','state'=>'state','country'=>'country',
            'pincode'=>'pincode','addressType'=>'address_type','isDefault'=>'is_default'];
    $c = [];
    foreach ($map as $in => $col) if (array_key_exists($in, $b)) $c[$col] = $b[$in];
    return $c;
}
function public_order($o) {
    return ['_id' => $o['id'], 'orderId' => $o['order_no'], 'orderNumber' => $o['order_no'],
            'items' => $o['items'] ?? [], 'totalAmount' => (float)($o['total_amount'] ?? 0),
            'status' => $o['status'] ?? null, 'paymentMethod' => $o['payment_method'] ?? null,
            'deliveryAddress' => $o['delivery_address'] ?? null, 'note' => $o['note'] ?? null,
            'user' => $o['user_id'] ?? null, 'createdAt' => $o['created_at'] ?? null];
}
function public_review($r) {
    return ['_id' => $r['id'], 'userName' => $r['user_name'] ?? null, 'rating' => $r['rating'] ?? 0,
            'title' => $r['title'] ?? '', 'body' => $r['body'] ?? '', 'createdAt' => $r['created_at'] ?? null];
}

function storage_upload($tmpPath, $origName, $mime) {
    $ext = strtolower(pathinfo($origName, PATHINFO_EXTENSION) ?: 'jpg');
    $key = time() . '-' . random_int(0, 9999) . '.' . $ext;
    list($code, $res) = http_req(SB_URL . '/storage/v1/object/uploads/' . $key, 'POST',
        ['apikey: ' . SB_KEY, 'Content-Type: ' . ($mime ?: 'application/octet-stream'), 'x-upsert: true'],
        file_get_contents($tmpPath));
    if ($code < 200 || $code >= 300) out(['error' => $res ?: 'Upload failed'], 500);
    return SB_URL . '/storage/v1/object/public/uploads/' . $key;
}
function storage_list($limit = 200) {
    list($code, $res) = http_req(SB_URL . '/storage/v1/object/list/uploads', 'POST',
        ['apikey: ' . SB_KEY, 'Authorization: Bearer ' . SB_KEY, 'Content-Type: application/json'],
        json_encode(['prefix' => '', 'limit' => $limit, 'offset' => 0, 'sortBy' => ['column' => 'created_at', 'order' => 'desc']]));
    if ($code < 200 || $code >= 300) out(['error' => $res ?: 'List failed'], 500);
    $rows = json_decode($res, true) ?: [];
    $files = [];
    foreach ($rows as $r) {
        if (empty($r['name']) || empty($r['id'])) continue;
        $files[] = ['name' => $r['name'], 'size' => $r['metadata']['size'] ?? null,
                    'createdAt' => $r['created_at'] ?? null,
                    'url' => SB_URL . '/storage/v1/object/public/uploads/' . $r['name']];
    }
    return $files;
}
function storage_delete($name) {
    list($code, $res) = http_req(SB_URL . '/storage/v1/object/uploads/' . rawurlencode($name), 'DELETE',
        ['apikey: ' . SB_KEY, 'Authorization: Bearer ' . SB_KEY]);
    if ($code < 200 || $code >= 300) out(['error' => $res ?: 'Delete failed'], 500);
    return true;
}
function sync_product_images($productId) {
    $rows = db_select('product_images', 'product_id=eq.' . $productId . '&select=*&order=is_primary.desc,sort_order.asc');
    $urls = array_values(array_map(function ($r) { return $r['image_url']; }, $rows));
    db_update('products', 'id=eq.' . $productId, ['image' => $urls[0] ?? null, 'images' => $urls, 'updated_at' => gmdate('c')]);
}

/* ---------------- routing ---------------- */

$splat = $_SERVER['PATH_INFO'] ?? '';
if ($splat === '') {
    $uri    = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
    $marker = '/api/public/index.php/';
    $pos    = strpos($uri, $marker);
    if ($pos !== false) $splat = substr($uri, $pos + strlen($marker));
    elseif (isset($_GET['__path'])) $splat = $_GET['__path'];
}
$seg    = array_values(array_filter(explode('/', strtok($splat, '?')), 'strlen'));
$method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
$raw    = file_get_contents('php://input');
$body   = in_array($method, ['POST', 'PUT', 'PATCH']) ? (json_decode($raw, true) ?: []) : [];

$a = $seg[0] ?? null; $b = $seg[1] ?? null; $c = $seg[2] ?? null; $d = $seg[3] ?? null;
$UUID = '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i';

/* ---- auth ---- */
if ($a === 'auth' && $b === 'register' && $method === 'POST') {
    $name = $body['name'] ?? $body['fullName'] ?? null;
    $email = strtolower(trim((string)($body['email'] ?? '')));
    $password = (string)($body['password'] ?? '');
    if (!$name || !$email || !$password) out(['error' => 'All fields are required.'], 400);
    if (strlen($password) < 6) out(['error' => 'Password must be at least 6 characters.'], 400);
    if (count(db_select('users', 'email=eq.' . rawurlencode($email) . '&auth_user_id=not.is.null&select=id')))
        out(['error' => 'Email already registered.'], 400);
    $au = create_auth_user($email, $password, ['full_name' => $name, 'phone' => $body['phone'] ?? $body['mobile'] ?? null]);
    if (isset($au['error'])) out(['error' => $au['error']], 400);
    $profile = ensure_profile($au, [
        'name' => $name, 'phone' => $body['phone'] ?? $body['mobile'] ?? null,
        'date_of_birth' => $body['dateOfBirth'] ?? null, 'gender' => $body['gender'] ?? null,
    ]);
    out(['success' => true, 'token' => sign_token(['sub' => $profile['id']]),
         'user' => public_user($profile), 'customer' => public_customer($profile)]);
}

if ($a === 'auth' && $b === 'login' && $method === 'POST') {
    $email = strtolower(trim((string)($body['email'] ?? '')));
    $password = (string)($body['password'] ?? '');
    $existing = first(db_select('users', 'email=eq.' . rawurlencode($email) . '&select=*&limit=1'));
    if ($existing && ($existing['status'] ?? '') === 'blocked')
        out(['error' => 'This account has been blocked. Please contact support.'], 403);
    $session = password_sign_in($email, $password);
    if ($session && !empty($session['access_token'])) {
        $au = auth_user($session['access_token']);
        $profile = ensure_profile($au);
        if (($profile['status'] ?? '') === 'blocked')
            out(['error' => 'This account has been blocked. Please contact support.'], 403);
        out(['success' => true, 'token' => sign_token(['sub' => $profile['id']]),
             'accessToken' => $session['access_token'],
             'user' => public_user($profile), 'customer' => public_customer($profile)]);
    }
    if ($existing && verify_password($password, $existing['password_hash'] ?? null)) {
        $au = create_auth_user($email, $password, ['full_name' => $existing['name'], 'phone' => $existing['phone']]);
        if (!isset($au['error']))
            db_update('users', 'id=eq.' . $existing['id'], ['auth_user_id' => $au['id'], 'password_hash' => null, 'updated_at' => gmdate('c')]);
        out(['success' => true, 'token' => sign_token(['sub' => $existing['id']]),
             'user' => public_user($existing), 'customer' => public_customer($existing)]);
    }
    out(['error' => 'Invalid email or password.'], 401);
}

if ($a === 'auth' && $b === 'sync' && $method === 'POST') {
    $au = auth_user(bearer());
    if (!$au) out(['error' => 'Unauthorized'], 401);
    $profile = ensure_profile($au, [
        'name' => $body['fullName'] ?? $body['name'] ?? null, 'phone' => $body['phone'] ?? null,
        'date_of_birth' => $body['dateOfBirth'] ?? null, 'gender' => $body['gender'] ?? null,
    ]);
    if (($profile['status'] ?? '') === 'blocked')
        out(['error' => 'This account has been blocked. Please contact support.'], 403);
    out(['success' => true, 'customer' => public_customer($profile)]);
}

if ($a === 'account' && ($b === 'me' || !$b)) {
    $me = current_user_row();
    if (!$me) out(['error' => 'Unauthorized'], 401);
    if ($method === 'GET') out(['success' => true, 'customer' => public_customer($me)]);
    if ($method === 'PUT') {
        $row = first(db_update('users', 'id=eq.' . $me['id'], customer_columns($body)));
        out(['success' => true, 'customer' => public_customer($row)]);
    }
}

if ($a === 'account' && $b === 'orders' && $method === 'GET') {
    $me = current_user_row();
    if (!$me) out(['error' => 'Unauthorized'], 401);
    $rows = db_select('orders', 'user_id=eq.' . $me['id'] . '&select=*&order=created_at.desc');
    out(['success' => true, 'orders' => array_map('public_order', $rows)]);
}

if ($a === 'guest' && $b === 'verify-otp' && $method === 'POST') {
    $phone = trim((string)($body['phone'] ?? ''));
    if (!preg_match('/^\d{10}$/', $phone)) out(['error' => 'Enter a valid 10-digit mobile number.'], 400);
    $t = sign_token(['guest' => true, 'phone' => $phone, 'name' => $body['name'] ?? 'Guest'], 2);
    out(['success' => true, 'guestToken' => $t, 'token' => $t]);
}

/* ---- public catalogue ---- */
if ($a === 'products' && !$b && $method === 'GET')
    out(array_map('public_product', db_select('products', 'status=eq.active&select=*&order=created_at.desc')));

if ($a === 'products' && $b && $method === 'GET' && preg_match($UUID, $b)) {
    $p = first(db_select('products', 'id=eq.' . $b . '&status=eq.active&select=*&limit=1'));
    if (!$p) out(['error' => 'Product not found'], 404);
    out(public_product($p));
}

if ($a === 'categories' && !$b && $method === 'GET')
    out(array_map('public_category', db_select('categories', 'status=eq.active&select=*&order=sort_order.asc')));

if ($a === 'settings' && !$b && $method === 'GET') {
    $settings = [];
    foreach (db_select('site_settings', 'select=*') as $r) $settings[$r['key']] = $r['value'];
    $homepage = [];
    foreach (db_select('homepage_content', 'select=*') as $r) $homepage[$r['key']] = $r['value'];
    out(['success' => true, 'settings' => (object)$settings, 'homepage' => (object)$homepage]);
}

if ($a === 'banners' && $method === 'GET' && !$b)
    out(db_select('banners', 'active=eq.true&select=*&order=sort_order.asc'));

if ($a === 'reviews' && $b) {
    if ($method === 'GET') {
        $rows = db_select('reviews', 'product_id=eq.' . $b . '&select=*&order=created_at.desc');
        $reviews = array_map('public_review', $rows);
        $breakdown = [1 => 0, 2 => 0, 3 => 0, 4 => 0, 5 => 0];
        $total = 0;
        foreach ($reviews as $r) {
            $rating = (int)$r['rating']; $total += $rating;
            if ($rating >= 1 && $rating <= 5) $breakdown[$rating]++;
        }
        $count = count($reviews);
        out(['reviews' => $reviews, 'count' => $count, 'avg' => $count ? $total / $count : 0, 'breakdown' => $breakdown]);
    }
    if ($method === 'POST') {
        $u = current_user_row();
        if (!$u) out(['error' => 'Please log in to write a review.'], 401);
        $r = first(db_insert('reviews', [
            'product_id' => $b, 'user_id' => $u['id'], 'user_name' => $u['name'],
            'rating' => (int)($body['rating'] ?? 5), 'title' => $body['title'] ?? '', 'body' => $body['body'] ?? '',
        ]));
        out(['success' => true, 'review' => public_review($r)]);
    }
}

if ($a === 'upload' && $method === 'POST') {
    if (!admin_user_row()) out(['error' => 'Admin access required'], 403);
    if (empty($_FILES['image']['tmp_name'])) out(['error' => 'No image uploaded'], 400);
    out(['success' => true, 'url' => storage_upload($_FILES['image']['tmp_name'], $_FILES['image']['name'], $_FILES['image']['type'] ?? '')]);
}

$user  = current_user_row();
$guest = $user ? null : verify_token(bearer());

/* ---- cart ---- */
if ($a === 'cart') {
    if (!$user) out(['error' => 'Unauthorized'], 401);
    if (!$b && $method === 'GET') {
        $rows = db_select('cart_items', 'user_id=eq.' . $user['id'] . '&select=*,products(*)&order=created_at.desc');
        $items = [];
        foreach ($rows as $r) {
            $p = public_product($r['products'] ?: []);
            $items[] = ['_id' => $r['id'], 'productId' => $r['product_id'], 'quantity' => $r['quantity'],
                        'name' => $p['name'], 'price' => $p['discountPrice'] ?? $p['price'],
                        'image' => $p['image'] ?: ($p['images'][0] ?? ''), 'stock' => $p['stock'],
                        'size' => $p['size'], 'product' => $p];
        }
        out(['success' => true, 'cart' => ['items' => $items]]);
    }
    if ($b === 'add' && $method === 'POST') {
        $pid = $body['productId'] ?? null; $qty = (int)($body['quantity'] ?? 1) ?: 1;
        $existing = first(db_select('cart_items', 'user_id=eq.' . $user['id'] . '&product_id=eq.' . $pid . '&select=*&limit=1'));
        if ($existing) db_update('cart_items', 'id=eq.' . $existing['id'], ['quantity' => $existing['quantity'] + $qty]);
        else db_insert('cart_items', ['user_id' => $user['id'], 'product_id' => $pid, 'quantity' => $qty]);
        out(['success' => true]);
    }
    if ($b === 'update' && $method === 'PUT') {
        $qty = (int)($body['quantity'] ?? 0);
        $filter = !empty($body['cartItemId']) ? 'id=eq.' . $body['cartItemId']
                : 'user_id=eq.' . $user['id'] . '&product_id=eq.' . ($body['productId'] ?? '');
        if ($qty <= 0) db_remove('cart_items', $filter);
        else db_update('cart_items', $filter, ['quantity' => $qty]);
        out(['success' => true]);
    }
    if ($b === 'remove' && $c && $method === 'DELETE') {
        $filter = preg_match($UUID, $c) ? 'id=eq.' . $c : 'user_id=eq.' . $user['id'] . '&product_id=eq.' . $c;
        db_remove('cart_items', $filter);
        out(['success' => true]);
    }
}

/* ---- wishlist ---- */
if ($a === 'wishlist') {
    if (!$user) out(['error' => 'Unauthorized'], 401);
    if (!$b && $method === 'GET') {
        $rows = db_select('wishlist', 'user_id=eq.' . $user['id'] . '&select=product_id');
        out(array_map(function ($r) { return ['_id' => $r['product_id']]; }, $rows));
    }
    if ($b === 'toggle' && $method === 'POST') {
        $pid = $body['productId'] ?? null;
        $existing = first(db_select('wishlist', 'user_id=eq.' . $user['id'] . '&product_id=eq.' . $pid . '&select=id&limit=1'));
        if ($existing) db_remove('wishlist', 'id=eq.' . $existing['id']);
        else db_insert('wishlist', ['user_id' => $user['id'], 'product_id' => $pid]);
        out(['success' => true, 'added' => !$existing]);
    }
}

/* ---- addresses ---- */
if ($a === 'addresses') {
    if (!$user) out(['error' => 'Unauthorized'], 401);
    if (!$b && $method === 'GET')
        out(['success' => true, 'addresses' => array_map('public_address',
            db_select('addresses', 'user_id=eq.' . $user['id'] . '&select=*&order=created_at.desc'))]);
    if (!$b && $method === 'POST') {
        $rows = db_select('addresses', 'user_id=eq.' . $user['id'] . '&select=id');
        $cols = address_columns($body);
        $cols['user_id'] = $user['id'];
        $cols['is_default'] = count($rows) === 0;
        out(['success' => true, 'address' => public_address(first(db_insert('addresses', $cols)))]);
    }
    if ($b && $method === 'PUT')
        out(['success' => true, 'address' => public_address(first(db_update('addresses',
            'id=eq.' . $b . '&user_id=eq.' . $user['id'], address_columns($body))))]);
    if ($b && $method === 'DELETE') {
        db_remove('addresses', 'id=eq.' . $b . '&user_id=eq.' . $user['id']);
        out(['success' => true]);
    }
}

if ($a === 'orders' && !$b && $method === 'GET') {
    if (!$user) out(['error' => 'Unauthorized'], 401);
    out(['success' => true, 'orders' => array_map('public_order',
        db_select('orders', 'user_id=eq.' . $user['id'] . '&select=*&order=created_at.desc'))]);
}

/* ---- checkout ---- */
if ($a === 'checkout' && ($b === 'cod' || $b === 'create-order') && $method === 'POST') {
    $items = $body['items'] ?? [];
    if (!count($items)) out(['error' => 'Your cart is empty.'], 400);
    $address = $body['guestDeliveryAddress'] ?? null;
    if (!$address && !empty($body['addressId']) && $user) {
        $row = first(db_select('addresses', 'id=eq.' . $body['addressId'] . '&user_id=eq.' . $user['id'] . '&select=*&limit=1'));
        $address = $row ? public_address($row) : null;
    }
    if (!$address) out(['error' => 'Please select a delivery address.'], 400);
    if ($b === 'create-order') out(['error' => 'Online payment is not configured yet. Please use Cash on Delivery.'], 400);
    $total = 0;
    foreach ($items as $i) $total += (float)($i['price'] ?? 0) * (int)($i['quantity'] ?? 1);
    $orderNo = 'DA' . substr((string)(time() * 1000), -8) . random_int(10, 99);
    $order = first(db_insert('orders', [
        'order_no' => $orderNo, 'user_id' => $user['id'] ?? null,
        'guest_name' => $guest['name'] ?? $address['fullName'] ?? null,
        'guest_phone' => $guest['phone'] ?? $address['mobile'] ?? null,
        'items' => $items, 'total_amount' => $total, 'payment_method' => 'COD',
        'status' => 'Pending', 'delivery_address' => $address, 'note' => $body['note'] ?? null,
    ]));
    if ($user) db_remove('cart_items', 'user_id=eq.' . $user['id']);
    out(['success' => true, 'orderId' => $order['order_no'], 'order' => public_order($order)]);
}

if ($a === 'checkout' && $b === 'verify-payment' && $method === 'POST')
    out(['error' => 'Online payment is not configured yet.'], 400);

/* ---- admin ---- */
if ($a === 'admin') {
    $admin = admin_user_row();
    if (!$admin) out(['error' => 'Admin access required'], 403);

    if ($b === 'me' && $method === 'GET') out(['success' => true, 'user' => public_user($admin)]);

    if ($b === 'stats' && $method === 'GET') {
        $users = db_select('users', 'select=id,role');
        $products = db_select('products', 'select=id,name,price,status,stock,image,category,created_at&order=created_at.desc');
        $categories = db_select('categories', 'select=id');
        $orders = db_select('orders', 'select=total_amount,status');
        $countStatus = function ($s) use ($products) {
            return count(array_filter($products, function ($p) use ($s) { return ($p['status'] ?? '') === $s; }));
        };
        $revenue = 0; $pending = 0;
        foreach ($orders as $o) { $revenue += (float)($o['total_amount'] ?? 0); if (($o['status'] ?? '') === 'Pending') $pending++; }
        $customers = array_filter($users, function ($u) { return ($u['role'] ?? '') !== 'admin'; });
        out(['success' => true, 'stats' => [
            'totalUsers' => count($users), 'totalCustomers' => count($customers),
            'totalProducts' => count($products), 'activeProducts' => $countStatus('active'),
            'draftProducts' => $countStatus('draft'), 'outOfStockProducts' => $countStatus('out_of_stock'),
            'totalCategories' => count($categories), 'totalOrders' => count($orders),
            'pendingOrders' => $pending, 'totalRevenue' => $revenue,
        ], 'recentProducts' => array_map('public_product', array_slice($products, 0, 6))]);
    }

    if ($b === 'categories') {
        if (!$c && $method === 'GET') {
            $rows = db_select('categories', 'select=*&order=sort_order.asc');
            $products = db_select('products', 'select=category_id');
            $cats = [];
            foreach ($rows as $r) {
                $cat = public_category($r);
                $cat['productCount'] = count(array_filter($products, function ($p) use ($r) { return ($p['category_id'] ?? null) === $r['id']; }));
                $cats[] = $cat;
            }
            out(['success' => true, 'categories' => $cats]);
        }
        if (!$c && $method === 'POST') {
            $cols = category_columns($body);
            if (empty($cols['name'])) out(['error' => 'Category name is required.'], 400);
            out(['success' => true, 'category' => public_category(first(db_insert('categories', $cols)))]);
        }
        if ($c && $method === 'PUT')
            out(['success' => true, 'category' => public_category(first(db_update('categories', 'id=eq.' . $c, category_columns($body))))]);
        if ($c && $method === 'DELETE') {
            if (count(db_select('products', 'category_id=eq.' . $c . '&select=id')))
                out(['error' => 'This category contains products. Please move or delete those products before deleting the category.'], 409);
            db_remove('categories', 'id=eq.' . $c);
            out(['success' => true]);
        }
    }

    if ($b === 'product-images') {
        if ($c && $method === 'GET')
            out(['success' => true, 'images' => array_map('public_product_image',
                db_select('product_images', 'product_id=eq.' . $c . '&select=*&order=sort_order.asc'))]);
        if (!$c && $method === 'POST') {
            $pid = $body['productId'] ?? null; $url = $body['url'] ?? null;
            if (!$pid || !$url) out(['error' => 'productId and url are required.'], 400);
            $existing = db_select('product_images', 'product_id=eq.' . $pid . '&select=id');
            $primary = !empty($body['isPrimary']) || count($existing) === 0;
            if ($primary) db_update('product_images', 'product_id=eq.' . $pid, ['is_primary' => false]);
            $row = first(db_insert('product_images', ['product_id' => $pid, 'image_url' => $url,
                'is_primary' => $primary, 'sort_order' => count($existing)]));
            sync_product_images($pid);
            out(['success' => true, 'image' => public_product_image($row)]);
        }
        if ($c && $method === 'PUT') {
            $img = first(db_select('product_images', 'id=eq.' . $c . '&select=*&limit=1'));
            if (!$img) out(['error' => 'Image not found'], 404);
            if (!empty($body['isPrimary'])) db_update('product_images', 'product_id=eq.' . $img['product_id'], ['is_primary' => false]);
            $patch = [];
            if (array_key_exists('isPrimary', $body)) $patch['is_primary'] = (bool)$body['isPrimary'];
            if (array_key_exists('sortOrder', $body)) $patch['sort_order'] = (int)$body['sortOrder'];
            if (count($patch)) db_update('product_images', 'id=eq.' . $c, $patch);
            sync_product_images($img['product_id']);
            out(['success' => true]);
        }
        if ($c && $method === 'DELETE') {
            $img = first(db_select('product_images', 'id=eq.' . $c . '&select=*&limit=1'));
            if (!$img) out(['error' => 'Image not found'], 404);
            db_remove('product_images', 'id=eq.' . $c);
            $rest = db_select('product_images', 'product_id=eq.' . $img['product_id'] . '&select=*&order=sort_order.asc');
            if (!empty($img['is_primary']) && count($rest)) db_update('product_images', 'id=eq.' . $rest[0]['id'], ['is_primary' => true]);
            sync_product_images($img['product_id']);
            out(['success' => true]);
        }
    }

    if ($b === 'media') {
        if (!$c && $method === 'GET') {
            $files = storage_list();
            $products = db_select('products', 'select=id,name,image,images');
            $categories = db_select('categories', 'select=id,name,image_url');
            $outFiles = [];
            foreach ($files as $f) {
                $usedBy = null;
                foreach ($products as $p) {
                    if (($p['image'] ?? null) === $f['url'] || in_array($f['url'], $p['images'] ?: [], true)) { $usedBy = $p['name']; break; }
                }
                if (!$usedBy) foreach ($categories as $cat) if (($cat['image_url'] ?? null) === $f['url']) { $usedBy = $cat['name']; break; }
                $f['usedBy'] = $usedBy;
                $outFiles[] = $f;
            }
            out(['success' => true, 'files' => $outFiles]);
        }
        if ($c && $method === 'DELETE') { storage_delete(rawurldecode($c)); out(['success' => true]); }
    }

    if ($b === 'settings') {
        if ($method === 'GET') {
            $settings = [];
            foreach (db_select('site_settings', 'select=*') as $r) $settings[$r['key']] = $r['value'];
            $homepage = [];
            foreach (db_select('homepage_content', 'select=*') as $r) $homepage[$r['key']] = $r['value'];
            out(['success' => true, 'settings' => (object)$settings, 'homepage' => (object)$homepage]);
        }
        if ($method === 'PUT') {
            $rows = [];
            foreach (($body['settings'] ?? []) as $k => $v)
                $rows[] = ['key' => $k, 'value' => $v === null ? null : (string)$v, 'updated_at' => gmdate('c')];
            if (count($rows)) db_upsert('site_settings', $rows, 'key');
            $hp = [];
            foreach (($body['homepage'] ?? []) as $k => $v)
                $hp[] = ['key' => $k, 'value' => $v, 'updated_at' => gmdate('c')];
            if (count($hp)) db_upsert('homepage_content', $hp, 'key');
            out(['success' => true]);
        }
    }

    if ($b === 'customers') {
        if (!$c && $method === 'GET') {
            $rows = db_select('users', 'select=*&order=created_at.desc');
            $orders = db_select('orders', 'select=user_id,total_amount,status');
            $customers = [];
            foreach ($rows as $r) {
                if (($r['role'] ?? '') === 'admin') continue;
                $mine = array_filter($orders, function ($o) use ($r) { return ($o['user_id'] ?? null) === $r['id']; });
                $spent = 0;
                foreach ($mine as $o) $spent += (float)($o['total_amount'] ?? 0);
                $cst = public_customer($r);
                $cst['totalOrders'] = count($mine);
                $cst['totalSpent'] = $spent;
                $cst['hasAuthAccount'] = !empty($r['auth_user_id']);
                $customers[] = $cst;
            }
            out(['success' => true, 'customers' => $customers]);
        }
        if ($c && !$d && $method === 'GET') {
            $row = first(db_select('users', 'id=eq.' . $c . '&select=*&limit=1'));
            if (!$row || ($row['role'] ?? '') === 'admin') out(['error' => 'Customer not found'], 404);
            $orders = db_select('orders', 'user_id=eq.' . $c . '&select=*&order=created_at.desc');
            $addresses = db_select('addresses', 'user_id=eq.' . $c . '&select=*');
            $spent = 0;
            foreach ($orders as $o) $spent += (float)($o['total_amount'] ?? 0);
            $cst = public_customer($row);
            $cst['hasAuthAccount'] = !empty($row['auth_user_id']);
            $cst['totalOrders'] = count($orders);
            $cst['totalSpent'] = $spent;
            out(['success' => true, 'customer' => $cst,
                 'orders' => array_map('public_order', $orders),
                 'addresses' => array_map('public_address', $addresses)]);
        }
        if ($c && $d === 'status' && $method === 'PUT') {
            $status = strtolower((string)($body['status'] ?? ''));
            if (!in_array($status, ['active', 'inactive', 'blocked'], true)) out(['error' => 'Invalid status.'], 400);
            $row = first(db_update('users', 'id=eq.' . $c, ['status' => $status, 'updated_at' => gmdate('c')]));
            out(['success' => true, 'customer' => public_customer($row)]);
        }
    }

    if ($b === 'users') {
        if (!$c && $method === 'GET')
            out(['success' => true, 'users' => array_map('public_user', db_select('users', 'select=*&order=created_at.desc'))]);
        if ($c && $d === 'role' && $method === 'PUT')
            out(['success' => true, 'user' => public_user(first(db_update('users', 'id=eq.' . $c, ['role' => $body['role'] ?? 'user'])))]);
    }

    if ($b === 'products') {
        if (!$c && $method === 'GET')
            out(['success' => true, 'products' => array_map('public_product', db_select('products', 'select=*&order=created_at.desc'))]);
        if (!$c && $method === 'POST') {
            $cols = product_columns($body);
            if (empty($cols['name'])) out(['error' => 'Product name is required.'], 400);
            if (empty($cols['category_id']) && empty($cols['category'])) out(['error' => 'Category is required.'], 400);
            if (!empty($cols['category_id'])) {
                $cat = first(db_select('categories', 'id=eq.' . $cols['category_id'] . '&select=slug&limit=1'));
                if ($cat) $cols['category'] = $cat['slug'];
            }
            $gallery = is_array($body['images'] ?? null) ? array_values(array_filter($body['images'])) : [];
            $cols['image'] = $cols['image'] ?? ($gallery[0] ?? null);
            $cols['images'] = $gallery;
            $row = first(db_insert('products', $cols));
            foreach ($gallery as $i => $url)
                db_insert('product_images', ['product_id' => $row['id'], 'image_url' => $url, 'is_primary' => $i === 0, 'sort_order' => $i]);
            out(['success' => true, 'product' => public_product($row)]);
        }
        if ($c && $method === 'PUT') {
            $cols = product_columns($body);
            if (!empty($cols['category_id'])) {
                $cat = first(db_select('categories', 'id=eq.' . $cols['category_id'] . '&select=slug&limit=1'));
                if ($cat) $cols['category'] = $cat['slug'];
            }
            $row = first(db_update('products', 'id=eq.' . $c, $cols));
            if (is_array($body['images'] ?? null)) {
                $gallery = array_values(array_filter($body['images']));
                db_remove('product_images', 'product_id=eq.' . $c);
                foreach ($gallery as $i => $url)
                    db_insert('product_images', ['product_id' => $c, 'image_url' => $url, 'is_primary' => $i === 0, 'sort_order' => $i]);
            }
            out(['success' => true, 'product' => public_product($row)]);
        }
        if ($c && $method === 'DELETE') {
            db_remove('product_images', 'product_id=eq.' . $c);
            db_remove('cart_items', 'product_id=eq.' . $c);
            db_remove('wishlist', 'product_id=eq.' . $c);
            db_remove('products', 'id=eq.' . $c);
            out(['success' => true]);
        }
    }

    if ($b === 'orders') {
        if (!$c && $method === 'GET')
            out(['success' => true, 'orders' => array_map('public_order', db_select('orders', 'select=*&order=created_at.desc'))]);
        if ($c && $d === 'status' && $method === 'PUT')
            out(['success' => true, 'order' => public_order(first(db_update('orders', 'id=eq.' . $c, ['status' => $body['status'] ?? 'Pending'])))]);
    }

    if ($b === 'banners') {
        if (!$c && $method === 'GET') out(['success' => true, 'banners' => db_select('banners', 'select=*&order=sort_order.asc')]);
        if (!$c && $method === 'POST') out(['success' => true, 'banner' => first(db_insert('banners', $body))]);
        if ($c && $method === 'PUT') out(['success' => true, 'banner' => first(db_update('banners', 'id=eq.' . $c, $body))]);
        if ($c && $method === 'DELETE') { db_remove('banners', 'id=eq.' . $c); out(['success' => true]); }
    }
}

out(['error' => 'Unknown endpoint: /' . implode('/', $seg)], 404);
