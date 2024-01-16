import fire


def start(c: str):
    from .app import config, db

    config.init(c)
    db.init(config.config.db_url)
    # TODO: run unicorn server


def db_init(c: str):
    from .app import config, db
    config.init(c)
    db.init(config.config.db_url)
    db.create_tables()
    # TODO: create admin user


def main():
    fire.Fire({
        'start': start,
        'db-init': db_init,
    })


if __name__ == '__main__':
    main()
