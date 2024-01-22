# WebQ

A queue system for web applications.

## Introduction
WebQ is a backend service designed for web applications to provide queue-related capabilities.
Currently, WebQ provides the following services:

* job-queue: A producer-consumer job queue, suitable for building crowd-sourcing applications.

## Installation
```
pip install webq
```

## Getting Started
### Generate a config file
You can generate a config file by running the following command as a starting point:
```
webq config-init > config.yml
```

### Initialize the database
If you are running the service for the first time, you need to initialize the database by running the following command:
```
webq db-init config.yml
```

This command will initialize the database according to the configuration file. It will create an `admin` user during the initialization. The password of the `admin` user will be printed out in the console. You can use this password to login to the admin user.

### Running the service
You can run the service by running the following command:
```
webq start config.yml
```
After the service is started, you can visit the OpenAPI documentation at `{base_url}/docs`.

## Services

### Job Queue
`job-queue` is a producer-consumer job queue. The producer can submit `job` to the queue with data or files payload. Then consumer can apply jobs from queue and submit the result (named `commit`) back to the queue when the job is resolved. And then the producer can retrieve the result from the queue.



## TODO
* [ ] E2E test
* [ ] Command line interface for basic operations
* [ ] Third party authentication
* [ ] Webhook support
* [ ] Refactor