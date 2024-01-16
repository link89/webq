import fire


def start(c: str):
    from .context import config, db

    config.init(c)
    db.init(config.config.db_url)
    # TODO: storage
    # TODO: run unicorn server


def db_init(c: str):
    from .context import config, db
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
