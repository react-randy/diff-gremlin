<?php
// Scanner-owned tokenizer: target source is data, never included or evaluated.
$input = json_decode(stream_get_contents(STDIN), true, 8, JSON_THROW_ON_ERROR);
$source = base64_decode($input['source'], true);
if ($source === false || !is_string($input['nonce'])) {
    exit(2);
}
$reply = [
    'schema' => 1, 'nonce' => $input['nonce'],
    'sha256' => hash('sha256', $source), 'version' => PHP_VERSION,
    'tokens' => [], 'parse_error' => null,
];
try {
    $tokens = token_get_all($source, TOKEN_PARSE);
    foreach ($tokens as $token) {
        $reply['tokens'][] = is_array($token)
            ? [token_name($token[0]), base64_encode($token[1])]
            : ['CHAR', base64_encode($token)];
    }
} catch (ParseError $error) {
    $reply['parse_error'] = ['line' => $error->getLine()];
}
echo json_encode($reply, JSON_THROW_ON_ERROR);
