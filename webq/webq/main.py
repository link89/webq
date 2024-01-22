import fire


def start(c: str):
    import uvicorn
    from .context import get_context, init

    init(c)
    ctx = get_context()
    config = ctx.config
    host, port = config.get_host_port()

    uvicorn.run("webq.app:app",
                host=host,
                port=port,
                log_level=config.data.log_level,
                )


def db_init(c: str):
    from .context import get_context, init
    init(c)
    ctx = get_context()
    ctx.db.create_tables()
    ctx.user_service.create_admin()


def config_init():
    from .config import CONFIG_EXAMPLE
    print(CONFIG_EXAMPLE)


def main():
    fire.Fire({
        'start': start,
        'db-init': db_init,
        'config-init': config_init,
    })


if __name__ == '__main__':
    main()
