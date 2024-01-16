import fire


def start(c: str):

    import uvicorn
    from .context import config, db


    config.init(c)
    db.init(config.config.db_url)
    # TODO: storage
    uvicorn.run("webq.app:app",
                host=config.config.host,
                port=config.config.port,
                log_level=config.config.log_level,
                )


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
