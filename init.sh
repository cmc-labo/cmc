#!/bin/bash

psql -U postgres -h localhost << EOF
  CREATE TABLE users ( id integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY, \
    username text NOT NULL UNIQUE, \
    password text NOT NULL, \
    nodetype text \
  );
  CREATE TABLE sessions ( \
    id integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY, \
    session_token text NOT NULL \
  );
EOF
exit $?