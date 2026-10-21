<?php
/* Reproduction-only setup endpoint. It runs before the OOM primer and is not
 * part of the control-flow trigger. Do not deploy this endpoint publicly. */
$sid = $_POST['sid'] ?? '';
$key = $_POST['key'] ?? '';
$value = $_POST['value'] ?? '0';
if ($sid === '' || strlen($sid) > 128) {
    http_response_code(400);
    exit("bad sid\n");
}
session_id($sid);
session_start();
$_SESSION[$key] = (int) $value;
session_write_close();
echo "seeded\n";
