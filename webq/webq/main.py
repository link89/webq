import fire


def start(c: str):
    import uvicorn
    from .context import get_context, init

    init(c)
    ctx = get_context()
    config = ctx.config.data

    uvicorn.run("webq.app:app",
                host=config.host,
                port=config.port,
                log_level=config.log_level,
                )


def db_init(c: str):
    from .context import get_context, init
    init(c)
    ctx = get_context()
    ctx.db.create_tables()
    ctx.user_service.create_admin()


def main():
    fire.Fire({
        'start': start,
        'db-init': db_init,
    })


if __name__ == '__main__':
    main()
