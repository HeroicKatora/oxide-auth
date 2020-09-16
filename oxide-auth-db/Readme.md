# oxide-auth-db

A DataBase Registrar Implementation.

## About
This cargo by-default provides a Redis Registrar Implementation.
Users can add different Database Implementation in db_service package.

And then use feature set to config which db you want to use in the Cargo.toml file.

`[features]`

`default = ["with-redis"]`

`with-redis = ["r2d2","r2d2_redis"]`


## Example
Users should have a redis server in his environment.
and run the commands below to add a test client to redis.

    ` set LocalClient "{\"client_id\":\"LocalClient\",\"redirect_uri\":\"http://localhost:8021/endpoint\",\"additional_redirect_uris\":[],\"default_scope\":\"default-scope\",\"client_secret\":\"$argon2i$v=19$m=4096,t=3,p=1$FAnLM+AwjNhHrKA2aCVxQDmbPHC6jc4xyiX1ioxr66g$7PXkjalEW6ynIrkWDY86zaplnox919Tbd+wlDOmhLDg\"}"`

then you can run the db-example.

> `$ cargo run db-example`

You may have to wait a second after the html page automatically opened.


Additional
----------
I license past and future contributions under the dual MIT/Apache-2.0 license, allowing licensees to chose either at their option.
