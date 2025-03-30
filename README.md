# PLEASE READ

<p align="center">
    <img alt="Solana" src="https://hpscript.s3.ap-northeast-1.amazonaws.com/cmc.png" width="100" />
</p>

# Building

## **1. Install rustc, cargo and rustfmt.**
```bash
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | /bin/bash -s -- -y
$ source $HOME/.cargo/env
$ rustup component add rustfmt
$ rustup update
```

```bash
$ cargo --version
$ rustc -V
```

On Linux systems you may need to install libssl-dev, pkg-config, zlib1g-dev, protobuf etc.

On Ubuntu, Debian:

```bash
$ yes | sudo apt-get update
$ yes | sudo apt-get upgrade
$ yes | sudo apt-get install libssl-dev libudev-dev pkg-config zlib1g-dev llvm clang cmake make libprotobuf-dev protobuf-compiler libpq-dev
```

## **2. Install PostgreSQL and set Password**
On Ubuntu, Debian:
---
```bash
$ yes | sudo apt install postgresql postgresql-contrib
$ psql --version
```
Once the postgres installation is complete, change the postgres password like the following procedure.

```bash
$ sudo -u postgres psql
ALTER ROLE postgres WITH password 'hogefuga';
\q
```


On Amazon Linux2023:
---
```bash
$ sudo yum install -y postgresql16-server
$ sudo postgresql-setup initdb
$ sudo systemctl start postgresql
$ systemctl status postgresql
$ sudo systemctl enable postgresql
$ psql --version
```
Once the postgres installation is complete, change the postgres password as stated above.

```bash
$ sudo -u postgres psql
ALTER ROLE postgres WITH password 'hogefuga';
\q
```
On RedHat:
---
```bash
$ sudo dnf -y install https://download.postgresql.org/pub/repos/yum/reporpms/EL-9-x86_64/pgdg-redhat-repo-latest.noarch.rpm
$ sudo dnf -y module disable postgresql
$ sudo dnf -y install postgresql16-server
$ /usr/pgsql-16/bin/initdb -E UTF8 --locale=C -A scram-sha-256 -W
$ sudo systemctl start postgresql-16.service
$ sudo systemctl enable postgresql-16.service
```

```bash
$ sudo vi /var/lib/pgsql/data/pg_hba.conf
# IPv4 local connections:
# host    all             all             127.0.0.1/32            ident
host    all             all             127.0.0.1/32            trust

$ sudo service postgresql restart
```
Once the postgres installation is complete, change the postgres password as stated above.

## **3. Download the source code.**

```bash
$ git clone https://github.com/cmc-labo/cmc
$ cd cmc
```

## **4. Set the psql password on .env file.**
Change .env_default in the root directory to .env and set the psql password you set like 'PSQL_PASSWORD=yourpassword'.

```bash
PSQL_PASSWORD=hogefuga
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_BUCKET_NAME=
AWS_REGION=
```

## **5. Execute Migration.**
```bash
$ chmod +x init.sh
$ ./init.sh
```

## **6. Build**
```bash
$ cargo run
```

Run the nohup & command to ensure that the process keeps running even if you close the virtual terminal or log out.
```bash
$ nohup cargo run &
```

## **7. SignUp the Wallet 🚀**
http://{your ip}:3000/signup


# Notice
- Please keep port 3000 open on your server.
- Please set the server specifications to Memory 2GB or more and Storage 20GB or more.