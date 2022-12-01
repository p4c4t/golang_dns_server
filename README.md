# golang_dns_server

## current state of the project
only supports one query per request
only tested for one answer per query

### TODO:
#### logical features
- implement multiple queries per requests
- implement multiple answers per queries
- implement both ipv4 and ipv6
- implement caching (which is the whole purpose of this server, i guess)
#### language features
- actually use golang's awesome multithreading!
- implement packet and individual query handling through streams
- refactor the code
- ask a golang developer about a more "go way" of doing things, because right know i just feel as if i was writing in C++