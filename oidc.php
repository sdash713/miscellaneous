<?php

// Register an OAuth app at 
// https://developer.okta.com/signup/

$client_id = 'test_client';
$client_secret = 'pBpmdGygT0nBjq2Llyp9wuoHMlsFtY31';
$metadata = http('http://10.27.122.198:8080/realms/master/.well-known/openid-configuration');

/*
$client_id = 'mMgsGASprKCmTtvI9WpGajpwkF48fTm2';
$client_secret = 'CJKg0rhpIdTd3yPpomM1MLAUjhajad18u4yHKAKAoOSLmZkpNohNe4mXxb3rSB9e';
$metadata = http('https://dev-s0gq7vhqvi4cdbrf.us.auth0.com/.well-known/openid-configuration');
*/

$ip = '10.27.122.198';
$port = '9099';


$redirect_uri = 'http://'.$ip.':'.$port.'/authorization-code/callback';
$socket_str = 'tcp://'.$ip.':'.$port;


$state = bin2hex(random_bytes(5));

$authorize_url = $metadata->authorization_endpoint.'?'.http_build_query([
  'response_type' => 'code',
  'client_id' => $client_id,
  'scope' => 'openid profile roles',
  'redirect_uri' => $redirect_uri,
  'state' => $state,
]);

echo "Open the following URL in a browser to continue\n";
echo $authorize_url."\n";
shell_exec("open '".$authorize_url."'");

// Start the mini HTTP server and wait for their browser to hit the redirect URL
// Store the query string parameters in a variable
$auth = startHttpServer($socket_str);

if($auth['state'] != $state) {
  echo "Wrong 'state' parameter returned\n";
  exit(2);
}

$code = $auth['code'];
print_r($auth);

echo "Received code=$code state=$state\n";

echo "Getting an access token...\n";
$response = http($metadata->token_endpoint, [
  'grant_type' => 'authorization_code',
  'code' => $code,
  'redirect_uri' => $redirect_uri,
  'client_id' => $client_id,
  'client_secret' => $client_secret,
]);

if(!isset($response->access_token)) {
  echo "Error fetching access token\n";
  exit(2);
}
print_r($response);

$access_token = $response->access_token;
echo  "access token is :- ".$access_token."\n";

echo "Getting the username...\n";
$token = http($metadata->introspection_endpoint, [
  'token' => $access_token,
  'client_id' => $client_id,
  'client_secret' => $client_secret,
]);


print_r($token);

echo "Get external token---\n";

$response = http($metadata->token_endpoint, [
  'grant_type' => 'urn:ietf:params:oauth:grant-type:token-exchange',
  'requested_issuer' =>'oidc',
  'subject_token' => $access_token,
  'requested_token_type' => 'urn:ietf:params:oauth:token-type:access_token',
  'client_id' => $client_id,
  'client_secret' => $client_secret,
]);

#'subject_token' => $access_token,
#'subject_token_type' => 'urn:ietf:params:oauth:token-type:access_token',
print_r($response);
if($token->active == 1) {
  echo "Logged in as ".$token->username."\n";
  die();
}



function startHttpServer($socketStr) {
  // Adapted from http://cweiske.de/shpub.htm

  $responseOk = "HTTP/1.0 200 OK\r\n"
    . "Content-Type: text/plain\r\n"
    . "\r\n"
    . "Ok. You may close this tab and return to the shell.\r\n";
  $responseErr = "HTTP/1.0 400 Bad Request\r\n"
    . "Content-Type: text/plain\r\n"
    . "\r\n"
    . "Bad Request\r\n";

  ini_set('default_socket_timeout', 60 * 5);

  $server = stream_socket_server($socketStr, $errno, $errstr);

  if(!$server) {
    Log::err('Error starting HTTP server');
    return false;
  }

  do {
    $sock = stream_socket_accept($server);
    if(!$sock) {
      Log::err('Error accepting socket connection');
      exit(1);
    }
    $headers = [];
    $body    = null;
    $content_length = 0;
    //read request headers
    while(false !== ($line = trim(fgets($sock)))) {
      if('' === $line) {
        break;
      }
      $regex = '#^Content-Length:\s*([[:digit:]]+)\s*$#i';
      if(preg_match($regex, $line, $matches)) {
        $content_length = (int)$matches[1];
      }
      $headers[] = $line;
    }
    // read content/body
    if($content_length > 0) {
      $body = fread($sock, $content_length);
    }
    // send response
    list($method, $url, $httpver) = explode(' ', $headers[0]);
    if($method == 'GET') {
      #echo "Redirected to $url\n";
      $parts = parse_url($url);
      #print_r($parts);
      if(isset($parts['path']) && $parts['path'] == '/authorization-code/callback'
        && isset($parts['query'])
      ) {
        parse_str($parts['query'], $query);
        if(isset($query['code']) && isset($query['state'])) {
          fwrite($sock, $responseOk);
          fclose($sock);
          return $query;
        }
      }
    }
    fwrite($sock, $responseErr);
    fclose($sock);
  } while (true);
}

function http($url, $params=false) {
  $ch = curl_init($url);
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
  if($params)
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params));
  return json_decode(curl_exec($ch));
}
