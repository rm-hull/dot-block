window.BENCHMARK_DATA = {
  "lastUpdate": 1785003358852,
  "repoUrl": "https://github.com/rm-hull/dot-block",
  "entries": {
    "dot-block benchmark": [
      {
        "commit": {
          "author": {
            "name": "rm-hull",
            "username": "rm-hull"
          },
          "committer": {
            "name": "rm-hull",
            "username": "rm-hull"
          },
          "id": "8fbd59117994594c9acfba49a1c107282d057739",
          "message": "feat: add benchmark tests",
          "timestamp": "2026-07-25T15:07:11Z",
          "url": "https://github.com/rm-hull/dot-block/pull/236/commits/8fbd59117994594c9acfba49a1c107282d057739"
        },
        "date": 1784996898067,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDNSDispatcher/CacheHit",
            "value": 5102,
            "unit": "ns/op\t    2346 B/op\t      43 allocs/op",
            "extra": "226902 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - ns/op",
            "value": 5102,
            "unit": "ns/op",
            "extra": "226902 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - B/op",
            "value": 2346,
            "unit": "B/op",
            "extra": "226902 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - allocs/op",
            "value": 43,
            "unit": "allocs/op",
            "extra": "226902 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss",
            "value": 110700,
            "unit": "ns/op\t    6805 B/op\t     116 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - ns/op",
            "value": 110700,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - B/op",
            "value": 6805,
            "unit": "B/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - allocs/op",
            "value": 116,
            "unit": "allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked",
            "value": 4576,
            "unit": "ns/op\t    2338 B/op\t      44 allocs/op",
            "extra": "259550 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - ns/op",
            "value": 4576,
            "unit": "ns/op",
            "extra": "259550 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - B/op",
            "value": 2338,
            "unit": "B/op",
            "extra": "259550 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "259550 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE",
            "value": 4772,
            "unit": "ns/op\t    2450 B/op\t      48 allocs/op",
            "extra": "233520 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - ns/op",
            "value": 4772,
            "unit": "ns/op",
            "extra": "233520 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - B/op",
            "value": 2450,
            "unit": "B/op",
            "extra": "233520 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - allocs/op",
            "value": 48,
            "unit": "allocs/op",
            "extra": "233520 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD",
            "value": 4847,
            "unit": "ns/op\t    2162 B/op\t      37 allocs/op",
            "extra": "260439 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - ns/op",
            "value": 4847,
            "unit": "ns/op",
            "extra": "260439 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - B/op",
            "value": 2162,
            "unit": "B/op",
            "extra": "260439 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - allocs/op",
            "value": 37,
            "unit": "allocs/op",
            "extra": "260439 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD",
            "value": 4286,
            "unit": "ns/op\t    2137 B/op\t      36 allocs/op",
            "extra": "251456 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - ns/op",
            "value": 4286,
            "unit": "ns/op",
            "extra": "251456 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - B/op",
            "value": 2137,
            "unit": "B/op",
            "extra": "251456 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - allocs/op",
            "value": 36,
            "unit": "allocs/op",
            "extra": "251456 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions",
            "value": 113337,
            "unit": "ns/op\t    7581 B/op\t     133 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - ns/op",
            "value": 113337,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - B/op",
            "value": 7581,
            "unit": "B/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - allocs/op",
            "value": 133,
            "unit": "allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS",
            "value": 6035,
            "unit": "ns/op\t    3670 B/op\t      61 allocs/op",
            "extra": "185595 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - ns/op",
            "value": 6035,
            "unit": "ns/op",
            "extra": "185595 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - B/op",
            "value": 3670,
            "unit": "B/op",
            "extra": "185595 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - allocs/op",
            "value": 61,
            "unit": "allocs/op",
            "extra": "185595 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent",
            "value": 2665,
            "unit": "ns/op\t    2321 B/op\t      42 allocs/op",
            "extra": "449659 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - ns/op",
            "value": 2665,
            "unit": "ns/op",
            "extra": "449659 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - B/op",
            "value": 2321,
            "unit": "B/op",
            "extra": "449659 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - allocs/op",
            "value": 42,
            "unit": "allocs/op",
            "extra": "449659 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get",
            "value": 164.6,
            "unit": "ns/op\t      88 B/op\t       3 allocs/op",
            "extra": "7292792 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - ns/op",
            "value": 164.6,
            "unit": "ns/op",
            "extra": "7292792 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - B/op",
            "value": 88,
            "unit": "B/op",
            "extra": "7292792 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "7292792 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set",
            "value": 456.6,
            "unit": "ns/op\t     128 B/op\t       4 allocs/op",
            "extra": "2522913 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - ns/op",
            "value": 456.6,
            "unit": "ns/op",
            "extra": "2522913 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - B/op",
            "value": 128,
            "unit": "B/op",
            "extra": "2522913 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "2522913 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient",
            "value": 79445,
            "unit": "ns/op\t    3387 B/op\t      56 allocs/op",
            "extra": "15016 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - ns/op",
            "value": 79445,
            "unit": "ns/op",
            "extra": "15016 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - B/op",
            "value": 3387,
            "unit": "B/op",
            "extra": "15016 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - allocs/op",
            "value": 56,
            "unit": "allocs/op",
            "extra": "15016 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "rm-hull",
            "username": "rm-hull"
          },
          "committer": {
            "name": "rm-hull",
            "username": "rm-hull"
          },
          "id": "60cb11c5ecff0c7d572b00d0fdd705aeaaef6f9d",
          "message": "feat: add benchmark tests",
          "timestamp": "2026-07-25T15:07:11Z",
          "url": "https://github.com/rm-hull/dot-block/pull/236/commits/60cb11c5ecff0c7d572b00d0fdd705aeaaef6f9d"
        },
        "date": 1784997645199,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDNSDispatcher/CacheHit",
            "value": 5244,
            "unit": "ns/op\t    2346 B/op\t      43 allocs/op",
            "extra": "223549 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - ns/op",
            "value": 5244,
            "unit": "ns/op",
            "extra": "223549 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - B/op",
            "value": 2346,
            "unit": "B/op",
            "extra": "223549 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - allocs/op",
            "value": 43,
            "unit": "allocs/op",
            "extra": "223549 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss",
            "value": 121557,
            "unit": "ns/op\t    6805 B/op\t     116 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - ns/op",
            "value": 121557,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - B/op",
            "value": 6805,
            "unit": "B/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - allocs/op",
            "value": 116,
            "unit": "allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked",
            "value": 4912,
            "unit": "ns/op\t    2338 B/op\t      44 allocs/op",
            "extra": "237039 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - ns/op",
            "value": 4912,
            "unit": "ns/op",
            "extra": "237039 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - B/op",
            "value": 2338,
            "unit": "B/op",
            "extra": "237039 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "237039 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE",
            "value": 5147,
            "unit": "ns/op\t    2450 B/op\t      48 allocs/op",
            "extra": "229347 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - ns/op",
            "value": 5147,
            "unit": "ns/op",
            "extra": "229347 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - B/op",
            "value": 2450,
            "unit": "B/op",
            "extra": "229347 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - allocs/op",
            "value": 48,
            "unit": "allocs/op",
            "extra": "229347 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD",
            "value": 5026,
            "unit": "ns/op\t    2161 B/op\t      37 allocs/op",
            "extra": "212601 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - ns/op",
            "value": 5026,
            "unit": "ns/op",
            "extra": "212601 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - B/op",
            "value": 2161,
            "unit": "B/op",
            "extra": "212601 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - allocs/op",
            "value": 37,
            "unit": "allocs/op",
            "extra": "212601 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD",
            "value": 4413,
            "unit": "ns/op\t    2137 B/op\t      36 allocs/op",
            "extra": "265118 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - ns/op",
            "value": 4413,
            "unit": "ns/op",
            "extra": "265118 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - B/op",
            "value": 2137,
            "unit": "B/op",
            "extra": "265118 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - allocs/op",
            "value": 36,
            "unit": "allocs/op",
            "extra": "265118 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions",
            "value": 122267,
            "unit": "ns/op\t    7587 B/op\t     132 allocs/op",
            "extra": "9357 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - ns/op",
            "value": 122267,
            "unit": "ns/op",
            "extra": "9357 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - B/op",
            "value": 7587,
            "unit": "B/op",
            "extra": "9357 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - allocs/op",
            "value": 132,
            "unit": "allocs/op",
            "extra": "9357 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS",
            "value": 6183,
            "unit": "ns/op\t    3744 B/op\t      61 allocs/op",
            "extra": "172800 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - ns/op",
            "value": 6183,
            "unit": "ns/op",
            "extra": "172800 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - B/op",
            "value": 3744,
            "unit": "B/op",
            "extra": "172800 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - allocs/op",
            "value": 61,
            "unit": "allocs/op",
            "extra": "172800 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent",
            "value": 2996,
            "unit": "ns/op\t    2321 B/op\t      42 allocs/op",
            "extra": "400947 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - ns/op",
            "value": 2996,
            "unit": "ns/op",
            "extra": "400947 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - B/op",
            "value": 2321,
            "unit": "B/op",
            "extra": "400947 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - allocs/op",
            "value": 42,
            "unit": "allocs/op",
            "extra": "400947 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get",
            "value": 174.7,
            "unit": "ns/op\t      88 B/op\t       3 allocs/op",
            "extra": "6857331 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - ns/op",
            "value": 174.7,
            "unit": "ns/op",
            "extra": "6857331 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - B/op",
            "value": 88,
            "unit": "B/op",
            "extra": "6857331 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "6857331 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set",
            "value": 494.2,
            "unit": "ns/op\t     133 B/op\t       4 allocs/op",
            "extra": "2415684 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - ns/op",
            "value": 494.2,
            "unit": "ns/op",
            "extra": "2415684 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - B/op",
            "value": 133,
            "unit": "B/op",
            "extra": "2415684 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "2415684 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient",
            "value": 94852,
            "unit": "ns/op\t    3386 B/op\t      56 allocs/op",
            "extra": "12292 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - ns/op",
            "value": 94852,
            "unit": "ns/op",
            "extra": "12292 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - B/op",
            "value": 3386,
            "unit": "B/op",
            "extra": "12292 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - allocs/op",
            "value": 56,
            "unit": "allocs/op",
            "extra": "12292 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "rm-hull",
            "username": "rm-hull"
          },
          "committer": {
            "name": "rm-hull",
            "username": "rm-hull"
          },
          "id": "21e4dc310a5cd152444ba6270e5dd247bac202b0",
          "message": "feat: add benchmark tests",
          "timestamp": "2026-07-25T15:07:11Z",
          "url": "https://github.com/rm-hull/dot-block/pull/236/commits/21e4dc310a5cd152444ba6270e5dd247bac202b0"
        },
        "date": 1784998199809,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDNSDispatcher/CacheHit",
            "value": 5190,
            "unit": "ns/op\t    2346 B/op\t      43 allocs/op",
            "extra": "220596 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - ns/op",
            "value": 5190,
            "unit": "ns/op",
            "extra": "220596 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - B/op",
            "value": 2346,
            "unit": "B/op",
            "extra": "220596 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - allocs/op",
            "value": 43,
            "unit": "allocs/op",
            "extra": "220596 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss",
            "value": 119790,
            "unit": "ns/op\t    6808 B/op\t     116 allocs/op",
            "extra": "9606 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - ns/op",
            "value": 119790,
            "unit": "ns/op",
            "extra": "9606 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - B/op",
            "value": 6808,
            "unit": "B/op",
            "extra": "9606 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - allocs/op",
            "value": 116,
            "unit": "allocs/op",
            "extra": "9606 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked",
            "value": 4655,
            "unit": "ns/op\t    2338 B/op\t      44 allocs/op",
            "extra": "256424 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - ns/op",
            "value": 4655,
            "unit": "ns/op",
            "extra": "256424 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - B/op",
            "value": 2338,
            "unit": "B/op",
            "extra": "256424 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "256424 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE",
            "value": 5345,
            "unit": "ns/op\t    2450 B/op\t      48 allocs/op",
            "extra": "220093 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - ns/op",
            "value": 5345,
            "unit": "ns/op",
            "extra": "220093 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - B/op",
            "value": 2450,
            "unit": "B/op",
            "extra": "220093 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - allocs/op",
            "value": 48,
            "unit": "allocs/op",
            "extra": "220093 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD",
            "value": 4747,
            "unit": "ns/op\t    2161 B/op\t      37 allocs/op",
            "extra": "250315 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - ns/op",
            "value": 4747,
            "unit": "ns/op",
            "extra": "250315 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - B/op",
            "value": 2161,
            "unit": "B/op",
            "extra": "250315 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - allocs/op",
            "value": 37,
            "unit": "allocs/op",
            "extra": "250315 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD",
            "value": 4338,
            "unit": "ns/op\t    2137 B/op\t      36 allocs/op",
            "extra": "274489 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - ns/op",
            "value": 4338,
            "unit": "ns/op",
            "extra": "274489 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - B/op",
            "value": 2137,
            "unit": "B/op",
            "extra": "274489 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - allocs/op",
            "value": 36,
            "unit": "allocs/op",
            "extra": "274489 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions",
            "value": 121390,
            "unit": "ns/op\t    7582 B/op\t     132 allocs/op",
            "extra": "9841 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - ns/op",
            "value": 121390,
            "unit": "ns/op",
            "extra": "9841 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - B/op",
            "value": 7582,
            "unit": "B/op",
            "extra": "9841 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - allocs/op",
            "value": 132,
            "unit": "allocs/op",
            "extra": "9841 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS",
            "value": 6033,
            "unit": "ns/op\t    3710 B/op\t      61 allocs/op",
            "extra": "181927 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - ns/op",
            "value": 6033,
            "unit": "ns/op",
            "extra": "181927 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - B/op",
            "value": 3710,
            "unit": "B/op",
            "extra": "181927 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - allocs/op",
            "value": 61,
            "unit": "allocs/op",
            "extra": "181927 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent",
            "value": 2890,
            "unit": "ns/op\t    2321 B/op\t      42 allocs/op",
            "extra": "405716 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - ns/op",
            "value": 2890,
            "unit": "ns/op",
            "extra": "405716 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - B/op",
            "value": 2321,
            "unit": "B/op",
            "extra": "405716 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - allocs/op",
            "value": 42,
            "unit": "allocs/op",
            "extra": "405716 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get",
            "value": 165,
            "unit": "ns/op\t      88 B/op\t       3 allocs/op",
            "extra": "7164867 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - ns/op",
            "value": 165,
            "unit": "ns/op",
            "extra": "7164867 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - B/op",
            "value": 88,
            "unit": "B/op",
            "extra": "7164867 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "7164867 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set",
            "value": 476.7,
            "unit": "ns/op\t     123 B/op\t       4 allocs/op",
            "extra": "2457836 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - ns/op",
            "value": 476.7,
            "unit": "ns/op",
            "extra": "2457836 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - B/op",
            "value": 123,
            "unit": "B/op",
            "extra": "2457836 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "2457836 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient",
            "value": 96975,
            "unit": "ns/op\t    3386 B/op\t      56 allocs/op",
            "extra": "12200 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - ns/op",
            "value": 96975,
            "unit": "ns/op",
            "extra": "12200 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - B/op",
            "value": 3386,
            "unit": "B/op",
            "extra": "12200 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - allocs/op",
            "value": 56,
            "unit": "allocs/op",
            "extra": "12200 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "rm-hull",
            "username": "rm-hull"
          },
          "committer": {
            "name": "rm-hull",
            "username": "rm-hull"
          },
          "id": "7afac93fe10fd68d1e920b6c104f7835ed19f8f2",
          "message": "feat: add benchmark tests",
          "timestamp": "2026-07-25T15:07:11Z",
          "url": "https://github.com/rm-hull/dot-block/pull/236/commits/7afac93fe10fd68d1e920b6c104f7835ed19f8f2"
        },
        "date": 1785003358052,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDNSDispatcher/CacheHit",
            "value": 5155,
            "unit": "ns/op\t    2346 B/op\t      43 allocs/op",
            "extra": "232212 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - ns/op",
            "value": 5155,
            "unit": "ns/op",
            "extra": "232212 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - B/op",
            "value": 2346,
            "unit": "B/op",
            "extra": "232212 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - allocs/op",
            "value": 43,
            "unit": "allocs/op",
            "extra": "232212 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss",
            "value": 117163,
            "unit": "ns/op\t    6805 B/op\t     116 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - ns/op",
            "value": 117163,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - B/op",
            "value": 6805,
            "unit": "B/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - allocs/op",
            "value": 116,
            "unit": "allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked",
            "value": 4654,
            "unit": "ns/op\t    2338 B/op\t      44 allocs/op",
            "extra": "257650 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - ns/op",
            "value": 4654,
            "unit": "ns/op",
            "extra": "257650 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - B/op",
            "value": 2338,
            "unit": "B/op",
            "extra": "257650 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "257650 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE",
            "value": 4915,
            "unit": "ns/op\t    2450 B/op\t      48 allocs/op",
            "extra": "246670 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - ns/op",
            "value": 4915,
            "unit": "ns/op",
            "extra": "246670 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - B/op",
            "value": 2450,
            "unit": "B/op",
            "extra": "246670 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - allocs/op",
            "value": 48,
            "unit": "allocs/op",
            "extra": "246670 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD",
            "value": 4633,
            "unit": "ns/op\t    2161 B/op\t      37 allocs/op",
            "extra": "260275 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - ns/op",
            "value": 4633,
            "unit": "ns/op",
            "extra": "260275 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - B/op",
            "value": 2161,
            "unit": "B/op",
            "extra": "260275 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - allocs/op",
            "value": 37,
            "unit": "allocs/op",
            "extra": "260275 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD",
            "value": 4360,
            "unit": "ns/op\t    2137 B/op\t      36 allocs/op",
            "extra": "274540 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - ns/op",
            "value": 4360,
            "unit": "ns/op",
            "extra": "274540 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - B/op",
            "value": 2137,
            "unit": "B/op",
            "extra": "274540 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - allocs/op",
            "value": 36,
            "unit": "allocs/op",
            "extra": "274540 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions",
            "value": 121492,
            "unit": "ns/op\t    7597 B/op\t     133 allocs/op",
            "extra": "8428 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - ns/op",
            "value": 121492,
            "unit": "ns/op",
            "extra": "8428 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - B/op",
            "value": 7597,
            "unit": "B/op",
            "extra": "8428 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - allocs/op",
            "value": 133,
            "unit": "allocs/op",
            "extra": "8428 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS",
            "value": 5858,
            "unit": "ns/op\t    3687 B/op\t      61 allocs/op",
            "extra": "190609 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - ns/op",
            "value": 5858,
            "unit": "ns/op",
            "extra": "190609 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - B/op",
            "value": 3687,
            "unit": "B/op",
            "extra": "190609 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - allocs/op",
            "value": 61,
            "unit": "allocs/op",
            "extra": "190609 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent",
            "value": 3106,
            "unit": "ns/op\t    2321 B/op\t      42 allocs/op",
            "extra": "389384 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - ns/op",
            "value": 3106,
            "unit": "ns/op",
            "extra": "389384 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - B/op",
            "value": 2321,
            "unit": "B/op",
            "extra": "389384 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - allocs/op",
            "value": 42,
            "unit": "allocs/op",
            "extra": "389384 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get",
            "value": 192.3,
            "unit": "ns/op\t      88 B/op\t       3 allocs/op",
            "extra": "5647149 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - ns/op",
            "value": 192.3,
            "unit": "ns/op",
            "extra": "5647149 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - B/op",
            "value": 88,
            "unit": "B/op",
            "extra": "5647149 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "5647149 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set",
            "value": 483.7,
            "unit": "ns/op\t     122 B/op\t       4 allocs/op",
            "extra": "2583610 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - ns/op",
            "value": 483.7,
            "unit": "ns/op",
            "extra": "2583610 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - B/op",
            "value": 122,
            "unit": "B/op",
            "extra": "2583610 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "2583610 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient",
            "value": 96473,
            "unit": "ns/op\t    3386 B/op\t      56 allocs/op",
            "extra": "12505 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - ns/op",
            "value": 96473,
            "unit": "ns/op",
            "extra": "12505 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - B/op",
            "value": 3386,
            "unit": "B/op",
            "extra": "12505 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - allocs/op",
            "value": 56,
            "unit": "allocs/op",
            "extra": "12505 times\n4 procs"
          }
        ]
      }
    ]
  }
}