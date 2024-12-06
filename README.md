# Authicantion service

## Install
### 1. Clone repository
```sh
git clone github.com/xomya40k/auth
```
### 3. Build and run
```sh
docker compose up
```
#### By default, the service is available at `http://localhost:8080`

## API
### Endpoint `Get`:
- Path: `/<user_uuid>`
- Method: `GET`
- Response:
```sh
{
    "status"        :   "OK",
    "access_token"  :   "<string>",
    "refresh_token" :   "<string>",
}
```
#### Valid format for `user_uuid`: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`

### Endpoint `Refresh`:
- Path: `/`
- Method: `POST`
- Request:
```sh
{
    "access_token"  :   "<string>",
    "refresh_token" :   "<string>",
}
```
- Response:
```sh
{
    "status"        :   "OK",
    "access_token"  :   "<string>",
    "refresh_token" :   "<string>",
}
```