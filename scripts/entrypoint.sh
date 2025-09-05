#!/bin/sh

set -e # exit if errors happen anywhere

flask init-db
flask run --host=0.0.0.0
