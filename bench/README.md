# Performance

## Benchmark setup

On receiving end we have HTTP client that binds to an IP on gateway interface of the machine and listens for HTTP requests.
For producing side, we setup a kind cluster with nat64 agent, create a pod and run `ab` from that pod to `64::ff9b::<IPv4 address of HTTP client>`.

## Results with NAT64 agent installed

Listening server: `python3 -m http.server 1234 --bind 1.2.3.4`
On pod in kind cluster: `ab -n 50000 http://64:ff9b::1.2.3.4:1234/`

```
This is ApacheBench, Version 2.3 <$Revision: 1913912 $>
Copyright 1996 Adam Twiss, Zeus Technology Ltd, http://www.zeustech.net/
Licensed to The Apache Software Foundation, http://www.apache.org/

Benchmarking 64:ff9b::1.2.3.4 (be patient)
Completed 5000 requests
Completed 10000 requests
Completed 15000 requests
Completed 20000 requests
Completed 25000 requests
Completed 30000 requests
Completed 35000 requests
Completed 40000 requests
Completed 45000 requests
Completed 50000 requests
Finished 50000 requests


Server Software:        SimpleHTTP/0.6
Server Hostname:        64:ff9b::1.2.3.4
Server Port:            1234

Document Path:          /
Document Length:        1442 bytes

Concurrency Level:      1
Time taken for tests:   130.277 seconds
Complete requests:      50000
Failed requests:        0
Total transferred:      79900000 bytes
HTML transferred:       72100000 bytes
Requests per second:    383.80 [#/sec] (mean)
Time per request:       2.606 [ms] (mean)
Time per request:       2.606 [ms] (mean, across all concurrent requests)
Transfer rate:          598.93 [Kbytes/sec] received

Connection Times (ms)
              min  mean[+/-sd] median   max
Connect:        0    0   0.0      0       1
Processing:     2    2   0.2      2       4
Waiting:        2    2   0.2      2       3
Total:          2    2   0.2      2       4

Percentage of the requests served within a certain time (ms)
  50%      2
  66%      3
  75%      3
  80%      3
  90%      3
  95%      3
  98%      3
  99%      3
 100%      4 (longest request)
```

## Reference point: no NAT64, local requests on host

Listening server: `python3 -m http.server 1234 --bind 1.2.3.4`
On host: `ab -n 50000 http://1.2.3.4:1234/`

```
This is ApacheBench, Version 2.3 <$Revision: 1923142 $>
Copyright 1996 Adam Twiss, Zeus Technology Ltd, http://www.zeustech.net/
Licensed to The Apache Software Foundation, http://www.apache.org/

Benchmarking 1.2.3.4 (be patient)
Completed 5000 requests
Completed 10000 requests
Completed 15000 requests
Completed 20000 requests
Completed 25000 requests
Completed 30000 requests
Completed 35000 requests
Completed 40000 requests
Completed 45000 requests
Completed 50000 requests
Finished 50000 requests


Server Software:        SimpleHTTP/0.6
Server Hostname:        1.2.3.4
Server Port:            1234

Document Path:          /
Document Length:        1442 bytes

Concurrency Level:      1
Time taken for tests:   118.559 seconds
Complete requests:      50000
Failed requests:        0
Total transferred:      79900000 bytes
HTML transferred:       72100000 bytes
Requests per second:    421.73 [#/sec] (mean)
Time per request:       2.371 [ms] (mean)
Time per request:       2.371 [ms] (mean, across all concurrent requests)
Transfer rate:          658.13 [Kbytes/sec] received

Connection Times (ms)
              min  mean[+/-sd] median   max
Connect:        0    0   0.0      0       0
Processing:     2    2   0.2      2       4
Waiting:        2    2   0.2      2       4
Total:          2    2   0.2      2       4

Percentage of the requests served within a certain time (ms)
  50%      2
  66%      2
  75%      2
  80%      2
  90%      3
  95%      3
  98%      3
  99%      3
 100%      4 (longest request)
```
