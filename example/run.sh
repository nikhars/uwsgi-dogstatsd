#!/bin/bash
uv pip install uWSGI==2.0.28

uwsgi --build-plugin ..

uwsgi app.ini
