<?php

file_put_contents("/Users/pj/htdocs/wozzit_python/listen.txt", print_r(file_get_contents('php://input'),true));

echo('{"wozzit": {}}');