window.BENCHMARK_DATA = {
  "lastUpdate": 1785494091872,
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
      },
      {
        "commit": {
          "author": {
            "email": "rm_hull@yahoo.co.uk",
            "name": "Richard Hull",
            "username": "rm-hull"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "b1d8abb7cfc08f7d5281959e4f2e84ce2ca61c2c",
          "message": "feat: add benchmark tests (#236)\n\n* test: add DNS-over-TLS query benchmarks\n\nIntroduce benchmarks to evaluate the performance and latency of\nDNS-over-TLS (DoT) queries.\n\n- `BenchmarkDoTQueryMultipleHosts`: Measures sequential lookups across\n  multiple domain names.\n- `BenchmarkDoTQueryConcurrent`: Measures performance using a worker\n  pool to track success rates and average latency under load.\n\n* feat: add automated benchmarks and workflow\n\nMove benchmarks to `internal/forwarder`, add documentation, and set up\nGitHub Actions workflow for continuous benchmarking.\n\n* ci: make benchmark job depend on build-go\n\nDisable external data path and lowercase benchmark job name to fix\nworkflow execution order and artifact dependencies.\n\n* style: fix linter errors in forwarder benchmarks\n\nIgnore unhandled errors from `server.Shutdown()` in benchmarks and\nfix minor whitespace alignment issues in test helpers.\n\n* docs: update benchmark results URL in README\n\nUpdate the benchmark results link to point to the new `/dev/bench/`\npath for improved documentation accuracy.\n\n* ci: split benchmark summary and chart update in workflow\n\nSeparate the CI workflow step for generating the benchmark summary table\nfrom pushing the historical chart data to prevent issues with missing\nexternal data paths.\n\n* ci: consolidate benchmark action configuration\n\nMerge benchmark summary and chart update steps into a single step to\nprevent duplicate runs and resolve missing data configuration issues.\n\n* refactor: adopt testing.B.Loop() in benchmarks\n\nUpdate forwarder benchmarks to use Go 1.24's `testing.B.Loop()` idiom\ninstead of traditional `for i := 0; i < b.N; i++` loops and explicit\ntimer resets.\n\n* ci: restrict benchmark auto-push and enable comments\n\nUpdate the GitHub Actions workflow to only auto-push benchmark results\non pushes to the main branch and enable persistent benchmarking comments\n on pull requests.",
          "timestamp": "2026-07-25T21:23:59+01:00",
          "tree_id": "07579fb6cf67104f20a438cd349073c88b8522ec",
          "url": "https://github.com/rm-hull/dot-block/commit/b1d8abb7cfc08f7d5281959e4f2e84ce2ca61c2c"
        },
        "date": 1785011231586,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDNSDispatcher/CacheHit",
            "value": 5033,
            "unit": "ns/op\t    2346 B/op\t      43 allocs/op",
            "extra": "216396 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - ns/op",
            "value": 5033,
            "unit": "ns/op",
            "extra": "216396 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - B/op",
            "value": 2346,
            "unit": "B/op",
            "extra": "216396 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - allocs/op",
            "value": 43,
            "unit": "allocs/op",
            "extra": "216396 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss",
            "value": 113939,
            "unit": "ns/op\t    6805 B/op\t     116 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - ns/op",
            "value": 113939,
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
            "value": 4639,
            "unit": "ns/op\t    2338 B/op\t      44 allocs/op",
            "extra": "266816 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - ns/op",
            "value": 4639,
            "unit": "ns/op",
            "extra": "266816 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - B/op",
            "value": 2338,
            "unit": "B/op",
            "extra": "266816 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "266816 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE",
            "value": 4890,
            "unit": "ns/op\t    2450 B/op\t      48 allocs/op",
            "extra": "245826 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - ns/op",
            "value": 4890,
            "unit": "ns/op",
            "extra": "245826 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - B/op",
            "value": 2450,
            "unit": "B/op",
            "extra": "245826 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - allocs/op",
            "value": 48,
            "unit": "allocs/op",
            "extra": "245826 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD",
            "value": 4673,
            "unit": "ns/op\t    2161 B/op\t      37 allocs/op",
            "extra": "251902 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - ns/op",
            "value": 4673,
            "unit": "ns/op",
            "extra": "251902 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - B/op",
            "value": 2161,
            "unit": "B/op",
            "extra": "251902 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - allocs/op",
            "value": 37,
            "unit": "allocs/op",
            "extra": "251902 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD",
            "value": 4376,
            "unit": "ns/op\t    2137 B/op\t      36 allocs/op",
            "extra": "277236 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - ns/op",
            "value": 4376,
            "unit": "ns/op",
            "extra": "277236 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - B/op",
            "value": 2137,
            "unit": "B/op",
            "extra": "277236 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - allocs/op",
            "value": 36,
            "unit": "allocs/op",
            "extra": "277236 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions",
            "value": 116081,
            "unit": "ns/op\t    7581 B/op\t     133 allocs/op",
            "extra": "9878 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - ns/op",
            "value": 116081,
            "unit": "ns/op",
            "extra": "9878 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - B/op",
            "value": 7581,
            "unit": "B/op",
            "extra": "9878 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - allocs/op",
            "value": 133,
            "unit": "allocs/op",
            "extra": "9878 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS",
            "value": 6593,
            "unit": "ns/op\t    3596 B/op\t      60 allocs/op",
            "extra": "158168 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - ns/op",
            "value": 6593,
            "unit": "ns/op",
            "extra": "158168 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - B/op",
            "value": 3596,
            "unit": "B/op",
            "extra": "158168 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "158168 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent",
            "value": 2892,
            "unit": "ns/op\t    2321 B/op\t      42 allocs/op",
            "extra": "404476 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - ns/op",
            "value": 2892,
            "unit": "ns/op",
            "extra": "404476 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - B/op",
            "value": 2321,
            "unit": "B/op",
            "extra": "404476 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - allocs/op",
            "value": 42,
            "unit": "allocs/op",
            "extra": "404476 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get",
            "value": 167.7,
            "unit": "ns/op\t      88 B/op\t       3 allocs/op",
            "extra": "7148558 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - ns/op",
            "value": 167.7,
            "unit": "ns/op",
            "extra": "7148558 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - B/op",
            "value": 88,
            "unit": "B/op",
            "extra": "7148558 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "7148558 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set",
            "value": 480.3,
            "unit": "ns/op\t     121 B/op\t       4 allocs/op",
            "extra": "2475796 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - ns/op",
            "value": 480.3,
            "unit": "ns/op",
            "extra": "2475796 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - B/op",
            "value": 121,
            "unit": "B/op",
            "extra": "2475796 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "2475796 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient",
            "value": 92046,
            "unit": "ns/op\t    3386 B/op\t      56 allocs/op",
            "extra": "13064 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - ns/op",
            "value": 92046,
            "unit": "ns/op",
            "extra": "13064 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - B/op",
            "value": 3386,
            "unit": "B/op",
            "extra": "13064 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - allocs/op",
            "value": 56,
            "unit": "allocs/op",
            "extra": "13064 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "rm_hull@yahoo.co.uk",
            "name": "Richard Hull",
            "username": "rm-hull"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "b64baca684f927278da11204fd6a6f0ec5bed27a",
          "message": "feat: implement YAML-based configuration with JSON schema and env substitution (#247)\n\n* feat: implement YAML-based configuration with JSON schema and env substitution (issue #238)\n\n- Add internal/config package with strongly-typed structs\n- Implement config loader with environment variable substitution\n- Add JSON schema generation and validation tests\n- Add --config flag to main.go\n- Generate and commit initial config.schema.json\n- Maintain backward compatibility with existing flags/env vars\n- Proper precedence: defaults < config.yaml < env vars < CLI flags\n\n* docs: add field descriptions to config JSON schema\n\n- Introduce a `CommentMap` in `internal/config/doc.go` to document all\nconfiguration fields.\n- Include the `$schema` draft 2020-12 reference in `config.schema.json`\nfor enhanced IDE support.\n- Update tests to ensure documentation comments remain in sync with the\nconfiguration structs.\n\n* refactor: remove redundant CLI flags in favor of config loader\n\nSimplify configuration handling by removing CLI flags and using robust\ninteger parsing for environment variable overrides.\n\n* feat: add XDG support to config file search path\n\nUpdate configuration loader to search standard XDG config directories\nalongside the local directory and `/etc/dot-block`, improving usability\nacross different operating systems and deployment models.\n\n* refactor: relax configuration schema and use pointers\n\n- Allow additional properties in JSON schema and set config fields as\npointers for optional overrides.\n- Add support for time.Duration strings with duration format in schema\ngeneration.\n\n* docs: update README with new configuration documentation\n\nDocument the new YAML-based configuration schema, environment variable\noverrides, configuration precedence, and schema generation instructions.\n\n* refactor: nest proxy protocol config under server settings\n\nRefactor the configuration schema and application structure to group\n`require_proxy_protocol` and `trusted_proxies` under a dedicated\n`proxy_protocol` object within `ServerConfig`.\n\n```mermaid\nerDiagram\n    ServerConfig ||--o{ ProxyProtocolConfig : contains\n    ServerConfig {\n        bool dev_mode\n        string log_level\n        int http_port\n        int dns_port\n        int dot_port\n    }\n    ProxyProtocolConfig {\n        bool enabled\n        string[] trusted_proxies\n    }\n```\n\n* docs: update AGENTS and README configuration docs\n\n- Clarify config schema generation requirements in `AGENTS.md` to\ninclude `CommentMap` updates in `doc.go`.\n- Document environment variable substitution syntax (`${VAR}` or\n`${VAR:-default}`) in the configuration guide.\n\n* refactor: clean up main configuration loading comments\n\nRemove redundant inline comments surrounding configuration loading and\nenvironment variable application steps in `main.go`.",
          "timestamp": "2026-07-26T01:06:54+01:00",
          "tree_id": "d7ab619082727131a11e0a1190d7de7c821fa4e7",
          "url": "https://github.com/rm-hull/dot-block/commit/b64baca684f927278da11204fd6a6f0ec5bed27a"
        },
        "date": 1785024607621,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDNSDispatcher/CacheHit",
            "value": 4987,
            "unit": "ns/op\t    2346 B/op\t      43 allocs/op",
            "extra": "225682 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - ns/op",
            "value": 4987,
            "unit": "ns/op",
            "extra": "225682 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - B/op",
            "value": 2346,
            "unit": "B/op",
            "extra": "225682 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - allocs/op",
            "value": 43,
            "unit": "allocs/op",
            "extra": "225682 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss",
            "value": 112048,
            "unit": "ns/op\t    6806 B/op\t     116 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - ns/op",
            "value": 112048,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - B/op",
            "value": 6806,
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
            "value": 4511,
            "unit": "ns/op\t    2338 B/op\t      44 allocs/op",
            "extra": "270314 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - ns/op",
            "value": 4511,
            "unit": "ns/op",
            "extra": "270314 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - B/op",
            "value": 2338,
            "unit": "B/op",
            "extra": "270314 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "270314 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE",
            "value": 4790,
            "unit": "ns/op\t    2450 B/op\t      48 allocs/op",
            "extra": "243448 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - ns/op",
            "value": 4790,
            "unit": "ns/op",
            "extra": "243448 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - B/op",
            "value": 2450,
            "unit": "B/op",
            "extra": "243448 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - allocs/op",
            "value": 48,
            "unit": "allocs/op",
            "extra": "243448 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD",
            "value": 5136,
            "unit": "ns/op\t    2162 B/op\t      37 allocs/op",
            "extra": "260620 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - ns/op",
            "value": 5136,
            "unit": "ns/op",
            "extra": "260620 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - B/op",
            "value": 2162,
            "unit": "B/op",
            "extra": "260620 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - allocs/op",
            "value": 37,
            "unit": "allocs/op",
            "extra": "260620 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD",
            "value": 4279,
            "unit": "ns/op\t    2137 B/op\t      36 allocs/op",
            "extra": "266287 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - ns/op",
            "value": 4279,
            "unit": "ns/op",
            "extra": "266287 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - B/op",
            "value": 2137,
            "unit": "B/op",
            "extra": "266287 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - allocs/op",
            "value": 36,
            "unit": "allocs/op",
            "extra": "266287 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions",
            "value": 114025,
            "unit": "ns/op\t    7582 B/op\t     133 allocs/op",
            "extra": "9825 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - ns/op",
            "value": 114025,
            "unit": "ns/op",
            "extra": "9825 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - B/op",
            "value": 7582,
            "unit": "B/op",
            "extra": "9825 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - allocs/op",
            "value": 133,
            "unit": "allocs/op",
            "extra": "9825 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS",
            "value": 6064,
            "unit": "ns/op\t    3710 B/op\t      61 allocs/op",
            "extra": "184572 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - ns/op",
            "value": 6064,
            "unit": "ns/op",
            "extra": "184572 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - B/op",
            "value": 3710,
            "unit": "B/op",
            "extra": "184572 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - allocs/op",
            "value": 61,
            "unit": "allocs/op",
            "extra": "184572 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent",
            "value": 2826,
            "unit": "ns/op\t    2321 B/op\t      42 allocs/op",
            "extra": "408906 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - ns/op",
            "value": 2826,
            "unit": "ns/op",
            "extra": "408906 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - B/op",
            "value": 2321,
            "unit": "B/op",
            "extra": "408906 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - allocs/op",
            "value": 42,
            "unit": "allocs/op",
            "extra": "408906 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get",
            "value": 170.9,
            "unit": "ns/op\t      88 B/op\t       3 allocs/op",
            "extra": "6888411 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - ns/op",
            "value": 170.9,
            "unit": "ns/op",
            "extra": "6888411 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - B/op",
            "value": 88,
            "unit": "B/op",
            "extra": "6888411 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "6888411 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set",
            "value": 492.6,
            "unit": "ns/op\t     133 B/op\t       4 allocs/op",
            "extra": "2468904 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - ns/op",
            "value": 492.6,
            "unit": "ns/op",
            "extra": "2468904 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - B/op",
            "value": 133,
            "unit": "B/op",
            "extra": "2468904 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "2468904 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient",
            "value": 91451,
            "unit": "ns/op\t    3386 B/op\t      56 allocs/op",
            "extra": "13102 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - ns/op",
            "value": 91451,
            "unit": "ns/op",
            "extra": "13102 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - B/op",
            "value": 3386,
            "unit": "B/op",
            "extra": "13102 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - allocs/op",
            "value": 56,
            "unit": "allocs/op",
            "extra": "13102 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "rm_hull@yahoo.co.uk",
            "name": "Richard Hull",
            "username": "rm-hull"
          },
          "committer": {
            "email": "rm_hull@yahoo.co.uk",
            "name": "Richard Hull",
            "username": "rm-hull"
          },
          "distinct": true,
          "id": "3b183a3d4548e9f7b44b516e6eaef43c1b1a80d7",
          "message": "refactor: migrate settings from env vars to YAML config\n\nMove Let's Encrypt, Telemetry, and IPInfo token settings out of direct\nenvironment variable reads and into the YAML configuration structure.\nEnvironment variables now serve as overrides via `ApplyEnvOverrides`.",
          "timestamp": "2026-07-26T12:34:18+01:00",
          "tree_id": "8ea91afb9949aebd2dbf1f348663eecbd86f8d87",
          "url": "https://github.com/rm-hull/dot-block/commit/3b183a3d4548e9f7b44b516e6eaef43c1b1a80d7"
        },
        "date": 1785065843299,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDNSDispatcher/CacheHit",
            "value": 5101,
            "unit": "ns/op\t    2346 B/op\t      43 allocs/op",
            "extra": "226196 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - ns/op",
            "value": 5101,
            "unit": "ns/op",
            "extra": "226196 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - B/op",
            "value": 2346,
            "unit": "B/op",
            "extra": "226196 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - allocs/op",
            "value": 43,
            "unit": "allocs/op",
            "extra": "226196 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss",
            "value": 112214,
            "unit": "ns/op\t    6805 B/op\t     116 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - ns/op",
            "value": 112214,
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
            "value": 4471,
            "unit": "ns/op\t    2338 B/op\t      44 allocs/op",
            "extra": "262792 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - ns/op",
            "value": 4471,
            "unit": "ns/op",
            "extra": "262792 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - B/op",
            "value": 2338,
            "unit": "B/op",
            "extra": "262792 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "262792 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE",
            "value": 4737,
            "unit": "ns/op\t    2450 B/op\t      48 allocs/op",
            "extra": "241273 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - ns/op",
            "value": 4737,
            "unit": "ns/op",
            "extra": "241273 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - B/op",
            "value": 2450,
            "unit": "B/op",
            "extra": "241273 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - allocs/op",
            "value": 48,
            "unit": "allocs/op",
            "extra": "241273 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD",
            "value": 4456,
            "unit": "ns/op\t    2162 B/op\t      37 allocs/op",
            "extra": "269611 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - ns/op",
            "value": 4456,
            "unit": "ns/op",
            "extra": "269611 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - B/op",
            "value": 2162,
            "unit": "B/op",
            "extra": "269611 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - allocs/op",
            "value": 37,
            "unit": "allocs/op",
            "extra": "269611 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD",
            "value": 4179,
            "unit": "ns/op\t    2137 B/op\t      36 allocs/op",
            "extra": "283652 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - ns/op",
            "value": 4179,
            "unit": "ns/op",
            "extra": "283652 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - B/op",
            "value": 2137,
            "unit": "B/op",
            "extra": "283652 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - allocs/op",
            "value": 36,
            "unit": "allocs/op",
            "extra": "283652 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions",
            "value": 115946,
            "unit": "ns/op\t    7582 B/op\t     133 allocs/op",
            "extra": "9842 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - ns/op",
            "value": 115946,
            "unit": "ns/op",
            "extra": "9842 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - B/op",
            "value": 7582,
            "unit": "B/op",
            "extra": "9842 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - allocs/op",
            "value": 133,
            "unit": "allocs/op",
            "extra": "9842 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS",
            "value": 5949,
            "unit": "ns/op\t    3731 B/op\t      61 allocs/op",
            "extra": "188454 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - ns/op",
            "value": 5949,
            "unit": "ns/op",
            "extra": "188454 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - B/op",
            "value": 3731,
            "unit": "B/op",
            "extra": "188454 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - allocs/op",
            "value": 61,
            "unit": "allocs/op",
            "extra": "188454 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent",
            "value": 3667,
            "unit": "ns/op\t    2321 B/op\t      42 allocs/op",
            "extra": "310136 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - ns/op",
            "value": 3667,
            "unit": "ns/op",
            "extra": "310136 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - B/op",
            "value": 2321,
            "unit": "B/op",
            "extra": "310136 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - allocs/op",
            "value": 42,
            "unit": "allocs/op",
            "extra": "310136 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get",
            "value": 165.4,
            "unit": "ns/op\t      88 B/op\t       3 allocs/op",
            "extra": "7211820 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - ns/op",
            "value": 165.4,
            "unit": "ns/op",
            "extra": "7211820 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - B/op",
            "value": 88,
            "unit": "B/op",
            "extra": "7211820 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "7211820 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set",
            "value": 462.1,
            "unit": "ns/op\t     118 B/op\t       4 allocs/op",
            "extra": "2536753 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - ns/op",
            "value": 462.1,
            "unit": "ns/op",
            "extra": "2536753 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - B/op",
            "value": 118,
            "unit": "B/op",
            "extra": "2536753 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "2536753 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient",
            "value": 92079,
            "unit": "ns/op\t    3387 B/op\t      56 allocs/op",
            "extra": "13012 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - ns/op",
            "value": 92079,
            "unit": "ns/op",
            "extra": "13012 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - B/op",
            "value": 3387,
            "unit": "B/op",
            "extra": "13012 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - allocs/op",
            "value": 56,
            "unit": "allocs/op",
            "extra": "13012 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "rm_hull@yahoo.co.uk",
            "name": "Richard Hull",
            "username": "rm-hull"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "e98a16aaa4bb599e405f251d6a251a3492ffb78d",
          "message": "fix: restore CNAME chain caching in DNS dispatcher (issue #250) (#251)\n\n* fix: restore CNAME chain caching in DNS dispatcher (issue #250)\n\nReplaces the naive exact name+type answer filtering with a CNAME-aware\nextractAnswersForQuestion function that follows CNAME chains to collect\nall relevant records. This restores CNAME chain caching while preserving\nmulti-question isolation (issue #225).\n\n- Add extractAnswersForQuestion helper that follows CNAME chains up to 8\n  levels and collects CNAME records, exact type matches, and A/AAAA\n  records for CNAME targets\n- Fix false-positive CNAME cache hit test (upstream was still running\n  during the 'cache hit' check; now directly verifies cache contents and\n  shuts down upstream to prove cache hit)\n- Add multi-level CNAME chain test (A -> B -> C -> IP)\n- Add benchmarkCacheHitCNAME benchmark\n\n* chore: remove deprecated test scripts and config files\n\n- Remove `config.proposed.yaml` as settings are now managed via\nconfig.yaml\n- Remove outdated implementation plan and stress test shell scripts\n\n* refactor: use modern range-over-int loop in CNAME chain extraction\n\nSimplify the loop counter by replacing `for i := 0; i < 8; i++` with\n`for range 8`, leveraging Go's newer range-over-int syntax.",
          "timestamp": "2026-07-26T13:16:18+01:00",
          "tree_id": "9fd479c13dd61249a2aa455d752d0c1b2f2f1dc9",
          "url": "https://github.com/rm-hull/dot-block/commit/e98a16aaa4bb599e405f251d6a251a3492ffb78d"
        },
        "date": 1785068338889,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDNSDispatcher/CacheHit",
            "value": 5058,
            "unit": "ns/op\t    2346 B/op\t      43 allocs/op",
            "extra": "229944 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - ns/op",
            "value": 5058,
            "unit": "ns/op",
            "extra": "229944 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - B/op",
            "value": 2346,
            "unit": "B/op",
            "extra": "229944 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - allocs/op",
            "value": 43,
            "unit": "allocs/op",
            "extra": "229944 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME",
            "value": 5207,
            "unit": "ns/op\t    2434 B/op\t      44 allocs/op",
            "extra": "219045 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - ns/op",
            "value": 5207,
            "unit": "ns/op",
            "extra": "219045 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - B/op",
            "value": 2434,
            "unit": "B/op",
            "extra": "219045 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "219045 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss",
            "value": 108113,
            "unit": "ns/op\t    6806 B/op\t     116 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - ns/op",
            "value": 108113,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - B/op",
            "value": 6806,
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
            "value": 4525,
            "unit": "ns/op\t    2338 B/op\t      44 allocs/op",
            "extra": "256638 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - ns/op",
            "value": 4525,
            "unit": "ns/op",
            "extra": "256638 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - B/op",
            "value": 2338,
            "unit": "B/op",
            "extra": "256638 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "256638 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE",
            "value": 4801,
            "unit": "ns/op\t    2450 B/op\t      48 allocs/op",
            "extra": "245653 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - ns/op",
            "value": 4801,
            "unit": "ns/op",
            "extra": "245653 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - B/op",
            "value": 2450,
            "unit": "B/op",
            "extra": "245653 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - allocs/op",
            "value": 48,
            "unit": "allocs/op",
            "extra": "245653 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD",
            "value": 4533,
            "unit": "ns/op\t    2162 B/op\t      37 allocs/op",
            "extra": "262018 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - ns/op",
            "value": 4533,
            "unit": "ns/op",
            "extra": "262018 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - B/op",
            "value": 2162,
            "unit": "B/op",
            "extra": "262018 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - allocs/op",
            "value": 37,
            "unit": "allocs/op",
            "extra": "262018 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD",
            "value": 4230,
            "unit": "ns/op\t    2138 B/op\t      36 allocs/op",
            "extra": "284484 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - ns/op",
            "value": 4230,
            "unit": "ns/op",
            "extra": "284484 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - B/op",
            "value": 2138,
            "unit": "B/op",
            "extra": "284484 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - allocs/op",
            "value": 36,
            "unit": "allocs/op",
            "extra": "284484 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions",
            "value": 107898,
            "unit": "ns/op\t    7581 B/op\t     133 allocs/op",
            "extra": "9918 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - ns/op",
            "value": 107898,
            "unit": "ns/op",
            "extra": "9918 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - B/op",
            "value": 7581,
            "unit": "B/op",
            "extra": "9918 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - allocs/op",
            "value": 133,
            "unit": "allocs/op",
            "extra": "9918 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS",
            "value": 5936,
            "unit": "ns/op\t    3680 B/op\t      61 allocs/op",
            "extra": "199291 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - ns/op",
            "value": 5936,
            "unit": "ns/op",
            "extra": "199291 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - B/op",
            "value": 3680,
            "unit": "B/op",
            "extra": "199291 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - allocs/op",
            "value": 61,
            "unit": "allocs/op",
            "extra": "199291 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent",
            "value": 2582,
            "unit": "ns/op\t    2321 B/op\t      42 allocs/op",
            "extra": "423405 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - ns/op",
            "value": 2582,
            "unit": "ns/op",
            "extra": "423405 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - B/op",
            "value": 2321,
            "unit": "B/op",
            "extra": "423405 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - allocs/op",
            "value": 42,
            "unit": "allocs/op",
            "extra": "423405 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get",
            "value": 165.6,
            "unit": "ns/op\t      88 B/op\t       3 allocs/op",
            "extra": "7185972 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - ns/op",
            "value": 165.6,
            "unit": "ns/op",
            "extra": "7185972 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - B/op",
            "value": 88,
            "unit": "B/op",
            "extra": "7185972 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "7185972 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set",
            "value": 449.7,
            "unit": "ns/op\t     130 B/op\t       4 allocs/op",
            "extra": "2665334 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - ns/op",
            "value": 449.7,
            "unit": "ns/op",
            "extra": "2665334 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - B/op",
            "value": 130,
            "unit": "B/op",
            "extra": "2665334 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "2665334 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient",
            "value": 78047,
            "unit": "ns/op\t    3387 B/op\t      56 allocs/op",
            "extra": "15200 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - ns/op",
            "value": 78047,
            "unit": "ns/op",
            "extra": "15200 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - B/op",
            "value": 3387,
            "unit": "B/op",
            "extra": "15200 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - allocs/op",
            "value": 56,
            "unit": "allocs/op",
            "extra": "15200 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "rm_hull@yahoo.co.uk",
            "name": "Richard Hull",
            "username": "rm-hull"
          },
          "committer": {
            "email": "rm_hull@yahoo.co.uk",
            "name": "Richard Hull",
            "username": "rm-hull"
          },
          "distinct": true,
          "id": "f0a24073e569ac647b33487a81ef4200874e1ef8",
          "message": "style: update Grafana dashboard metrics and visualizations [skip-ci]\n\nImprove observability panels in the dashboard definition by fixing\nPrometheus\nquery groups, updating metric expressions (e.g., `dns_country_count` to\n`dns_provider_count`), and tuning visual thresholds and graph modes.",
          "timestamp": "2026-07-26T13:49:58+01:00",
          "tree_id": "e968092f1b46bdb26d557651cf27cafbb695df27",
          "url": "https://github.com/rm-hull/dot-block/commit/f0a24073e569ac647b33487a81ef4200874e1ef8"
        },
        "date": 1785070396495,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDNSDispatcher/CacheHit",
            "value": 5233,
            "unit": "ns/op\t    2346 B/op\t      43 allocs/op",
            "extra": "223784 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - ns/op",
            "value": 5233,
            "unit": "ns/op",
            "extra": "223784 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - B/op",
            "value": 2346,
            "unit": "B/op",
            "extra": "223784 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - allocs/op",
            "value": 43,
            "unit": "allocs/op",
            "extra": "223784 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME",
            "value": 5415,
            "unit": "ns/op\t    2434 B/op\t      44 allocs/op",
            "extra": "218174 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - ns/op",
            "value": 5415,
            "unit": "ns/op",
            "extra": "218174 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - B/op",
            "value": 2434,
            "unit": "B/op",
            "extra": "218174 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "218174 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss",
            "value": 120378,
            "unit": "ns/op\t    6810 B/op\t     116 allocs/op",
            "extra": "9387 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - ns/op",
            "value": 120378,
            "unit": "ns/op",
            "extra": "9387 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - B/op",
            "value": 6810,
            "unit": "B/op",
            "extra": "9387 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - allocs/op",
            "value": 116,
            "unit": "allocs/op",
            "extra": "9387 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked",
            "value": 4681,
            "unit": "ns/op\t    2338 B/op\t      44 allocs/op",
            "extra": "256004 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - ns/op",
            "value": 4681,
            "unit": "ns/op",
            "extra": "256004 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - B/op",
            "value": 2338,
            "unit": "B/op",
            "extra": "256004 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "256004 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE",
            "value": 5002,
            "unit": "ns/op\t    2450 B/op\t      48 allocs/op",
            "extra": "243300 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - ns/op",
            "value": 5002,
            "unit": "ns/op",
            "extra": "243300 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - B/op",
            "value": 2450,
            "unit": "B/op",
            "extra": "243300 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - allocs/op",
            "value": 48,
            "unit": "allocs/op",
            "extra": "243300 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD",
            "value": 4614,
            "unit": "ns/op\t    2162 B/op\t      37 allocs/op",
            "extra": "252466 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - ns/op",
            "value": 4614,
            "unit": "ns/op",
            "extra": "252466 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - B/op",
            "value": 2162,
            "unit": "B/op",
            "extra": "252466 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - allocs/op",
            "value": 37,
            "unit": "allocs/op",
            "extra": "252466 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD",
            "value": 4643,
            "unit": "ns/op\t    2137 B/op\t      36 allocs/op",
            "extra": "273062 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - ns/op",
            "value": 4643,
            "unit": "ns/op",
            "extra": "273062 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - B/op",
            "value": 2137,
            "unit": "B/op",
            "extra": "273062 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - allocs/op",
            "value": 36,
            "unit": "allocs/op",
            "extra": "273062 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions",
            "value": 124363,
            "unit": "ns/op\t    7596 B/op\t     133 allocs/op",
            "extra": "8538 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - ns/op",
            "value": 124363,
            "unit": "ns/op",
            "extra": "8538 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - B/op",
            "value": 7596,
            "unit": "B/op",
            "extra": "8538 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - allocs/op",
            "value": 133,
            "unit": "allocs/op",
            "extra": "8538 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS",
            "value": 6094,
            "unit": "ns/op\t    3738 B/op\t      61 allocs/op",
            "extra": "181558 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - ns/op",
            "value": 6094,
            "unit": "ns/op",
            "extra": "181558 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - B/op",
            "value": 3738,
            "unit": "B/op",
            "extra": "181558 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - allocs/op",
            "value": 61,
            "unit": "allocs/op",
            "extra": "181558 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent",
            "value": 2872,
            "unit": "ns/op\t    2321 B/op\t      42 allocs/op",
            "extra": "414247 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - ns/op",
            "value": 2872,
            "unit": "ns/op",
            "extra": "414247 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - B/op",
            "value": 2321,
            "unit": "B/op",
            "extra": "414247 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - allocs/op",
            "value": 42,
            "unit": "allocs/op",
            "extra": "414247 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get",
            "value": 166.4,
            "unit": "ns/op\t      88 B/op\t       3 allocs/op",
            "extra": "7168975 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - ns/op",
            "value": 166.4,
            "unit": "ns/op",
            "extra": "7168975 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - B/op",
            "value": 88,
            "unit": "B/op",
            "extra": "7168975 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "7168975 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set",
            "value": 504,
            "unit": "ns/op\t     137 B/op\t       4 allocs/op",
            "extra": "2381232 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - ns/op",
            "value": 504,
            "unit": "ns/op",
            "extra": "2381232 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - B/op",
            "value": 137,
            "unit": "B/op",
            "extra": "2381232 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "2381232 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient",
            "value": 98897,
            "unit": "ns/op\t    3387 B/op\t      56 allocs/op",
            "extra": "12176 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - ns/op",
            "value": 98897,
            "unit": "ns/op",
            "extra": "12176 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - B/op",
            "value": 3387,
            "unit": "B/op",
            "extra": "12176 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - allocs/op",
            "value": 56,
            "unit": "allocs/op",
            "extra": "12176 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "rm_hull@yahoo.co.uk",
            "name": "Richard Hull",
            "username": "rm-hull"
          },
          "committer": {
            "email": "rm_hull@yahoo.co.uk",
            "name": "Richard Hull",
            "username": "rm-hull"
          },
          "distinct": true,
          "id": "e4774d14b2d388971f9d7f2e4fc19befd9f9def0",
          "message": "feat: add configurable top-K tracking for Prometheus metrics\n\nAdd `top_k` configuration block to allow tuning the size of\nMisra-Gries space-saving sketches for top domains, blocked domains,\nand clients. Update configuration loader, JSON schema, and metrics\ninitialization.",
          "timestamp": "2026-07-26T18:38:25+01:00",
          "tree_id": "f911be9cf2f9fa03fbdd176c8b9c6b0bb44806ac",
          "url": "https://github.com/rm-hull/dot-block/commit/e4774d14b2d388971f9d7f2e4fc19befd9f9def0"
        },
        "date": 1785090515285,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDNSDispatcher/CacheHit",
            "value": 5171,
            "unit": "ns/op\t    2346 B/op\t      43 allocs/op",
            "extra": "226644 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - ns/op",
            "value": 5171,
            "unit": "ns/op",
            "extra": "226644 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - B/op",
            "value": 2346,
            "unit": "B/op",
            "extra": "226644 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - allocs/op",
            "value": 43,
            "unit": "allocs/op",
            "extra": "226644 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME",
            "value": 5296,
            "unit": "ns/op\t    2434 B/op\t      44 allocs/op",
            "extra": "226053 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - ns/op",
            "value": 5296,
            "unit": "ns/op",
            "extra": "226053 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - B/op",
            "value": 2434,
            "unit": "B/op",
            "extra": "226053 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "226053 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss",
            "value": 115324,
            "unit": "ns/op\t    6805 B/op\t     116 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - ns/op",
            "value": 115324,
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
            "value": 4630,
            "unit": "ns/op\t    2338 B/op\t      44 allocs/op",
            "extra": "261520 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - ns/op",
            "value": 4630,
            "unit": "ns/op",
            "extra": "261520 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - B/op",
            "value": 2338,
            "unit": "B/op",
            "extra": "261520 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "261520 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE",
            "value": 4864,
            "unit": "ns/op\t    2450 B/op\t      48 allocs/op",
            "extra": "249012 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - ns/op",
            "value": 4864,
            "unit": "ns/op",
            "extra": "249012 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - B/op",
            "value": 2450,
            "unit": "B/op",
            "extra": "249012 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - allocs/op",
            "value": 48,
            "unit": "allocs/op",
            "extra": "249012 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD",
            "value": 4604,
            "unit": "ns/op\t    2161 B/op\t      37 allocs/op",
            "extra": "263878 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - ns/op",
            "value": 4604,
            "unit": "ns/op",
            "extra": "263878 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - B/op",
            "value": 2161,
            "unit": "B/op",
            "extra": "263878 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - allocs/op",
            "value": 37,
            "unit": "allocs/op",
            "extra": "263878 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD",
            "value": 4312,
            "unit": "ns/op\t    2137 B/op\t      36 allocs/op",
            "extra": "278955 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - ns/op",
            "value": 4312,
            "unit": "ns/op",
            "extra": "278955 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - B/op",
            "value": 2137,
            "unit": "B/op",
            "extra": "278955 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - allocs/op",
            "value": 36,
            "unit": "allocs/op",
            "extra": "278955 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions",
            "value": 117569,
            "unit": "ns/op\t    7584 B/op\t     132 allocs/op",
            "extra": "9639 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - ns/op",
            "value": 117569,
            "unit": "ns/op",
            "extra": "9639 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - B/op",
            "value": 7584,
            "unit": "B/op",
            "extra": "9639 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - allocs/op",
            "value": 132,
            "unit": "allocs/op",
            "extra": "9639 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS",
            "value": 6674,
            "unit": "ns/op\t    3703 B/op\t      61 allocs/op",
            "extra": "180900 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - ns/op",
            "value": 6674,
            "unit": "ns/op",
            "extra": "180900 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - B/op",
            "value": 3703,
            "unit": "B/op",
            "extra": "180900 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - allocs/op",
            "value": 61,
            "unit": "allocs/op",
            "extra": "180900 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent",
            "value": 2837,
            "unit": "ns/op\t    2321 B/op\t      42 allocs/op",
            "extra": "394951 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - ns/op",
            "value": 2837,
            "unit": "ns/op",
            "extra": "394951 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - B/op",
            "value": 2321,
            "unit": "B/op",
            "extra": "394951 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - allocs/op",
            "value": 42,
            "unit": "allocs/op",
            "extra": "394951 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get",
            "value": 169.1,
            "unit": "ns/op\t      88 B/op\t       3 allocs/op",
            "extra": "7037616 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - ns/op",
            "value": 169.1,
            "unit": "ns/op",
            "extra": "7037616 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - B/op",
            "value": 88,
            "unit": "B/op",
            "extra": "7037616 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "7037616 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set",
            "value": 456.7,
            "unit": "ns/op\t     124 B/op\t       4 allocs/op",
            "extra": "2671192 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - ns/op",
            "value": 456.7,
            "unit": "ns/op",
            "extra": "2671192 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - B/op",
            "value": 124,
            "unit": "B/op",
            "extra": "2671192 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "2671192 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient",
            "value": 92442,
            "unit": "ns/op\t    3387 B/op\t      56 allocs/op",
            "extra": "12937 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - ns/op",
            "value": 92442,
            "unit": "ns/op",
            "extra": "12937 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - B/op",
            "value": 3387,
            "unit": "B/op",
            "extra": "12937 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - allocs/op",
            "value": 56,
            "unit": "allocs/op",
            "extra": "12937 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "283124303+go-dependency-updates[bot]@users.noreply.github.com",
            "name": "go-dependency-updates[bot]",
            "username": "go-dependency-updates[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "9a2f099f38df35eb8c3e8bf42bf037f4d92ec576",
          "message": "chore: go get -u && go mod tidy (#252)\n\nCo-authored-by: rm-hull <1915543+rm-hull@users.noreply.github.com>",
          "timestamp": "2026-07-27T07:47:55+01:00",
          "tree_id": "179ac258fe4f6e1ae69be629c6c80b90bb48f566",
          "url": "https://github.com/rm-hull/dot-block/commit/9a2f099f38df35eb8c3e8bf42bf037f4d92ec576"
        },
        "date": 1785135058773,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDNSDispatcher/CacheHit",
            "value": 5048,
            "unit": "ns/op\t    2346 B/op\t      43 allocs/op",
            "extra": "229899 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - ns/op",
            "value": 5048,
            "unit": "ns/op",
            "extra": "229899 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - B/op",
            "value": 2346,
            "unit": "B/op",
            "extra": "229899 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - allocs/op",
            "value": 43,
            "unit": "allocs/op",
            "extra": "229899 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME",
            "value": 5147,
            "unit": "ns/op\t    2434 B/op\t      44 allocs/op",
            "extra": "224632 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - ns/op",
            "value": 5147,
            "unit": "ns/op",
            "extra": "224632 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - B/op",
            "value": 2434,
            "unit": "B/op",
            "extra": "224632 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "224632 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss",
            "value": 108687,
            "unit": "ns/op\t    6805 B/op\t     116 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - ns/op",
            "value": 108687,
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
            "value": 4544,
            "unit": "ns/op\t    2338 B/op\t      44 allocs/op",
            "extra": "257625 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - ns/op",
            "value": 4544,
            "unit": "ns/op",
            "extra": "257625 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - B/op",
            "value": 2338,
            "unit": "B/op",
            "extra": "257625 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "257625 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE",
            "value": 4779,
            "unit": "ns/op\t    2450 B/op\t      48 allocs/op",
            "extra": "248780 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - ns/op",
            "value": 4779,
            "unit": "ns/op",
            "extra": "248780 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - B/op",
            "value": 2450,
            "unit": "B/op",
            "extra": "248780 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - allocs/op",
            "value": 48,
            "unit": "allocs/op",
            "extra": "248780 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD",
            "value": 4870,
            "unit": "ns/op\t    2161 B/op\t      37 allocs/op",
            "extra": "268740 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - ns/op",
            "value": 4870,
            "unit": "ns/op",
            "extra": "268740 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - B/op",
            "value": 2161,
            "unit": "B/op",
            "extra": "268740 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - allocs/op",
            "value": 37,
            "unit": "allocs/op",
            "extra": "268740 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD",
            "value": 4189,
            "unit": "ns/op\t    2137 B/op\t      36 allocs/op",
            "extra": "270224 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - ns/op",
            "value": 4189,
            "unit": "ns/op",
            "extra": "270224 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - B/op",
            "value": 2137,
            "unit": "B/op",
            "extra": "270224 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - allocs/op",
            "value": 36,
            "unit": "allocs/op",
            "extra": "270224 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions",
            "value": 112175,
            "unit": "ns/op\t    7582 B/op\t     133 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - ns/op",
            "value": 112175,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - B/op",
            "value": 7582,
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
            "value": 5771,
            "unit": "ns/op\t    3671 B/op\t      61 allocs/op",
            "extra": "198045 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - ns/op",
            "value": 5771,
            "unit": "ns/op",
            "extra": "198045 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - B/op",
            "value": 3671,
            "unit": "B/op",
            "extra": "198045 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - allocs/op",
            "value": 61,
            "unit": "allocs/op",
            "extra": "198045 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent",
            "value": 2760,
            "unit": "ns/op\t    2321 B/op\t      42 allocs/op",
            "extra": "446516 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - ns/op",
            "value": 2760,
            "unit": "ns/op",
            "extra": "446516 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - B/op",
            "value": 2321,
            "unit": "B/op",
            "extra": "446516 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - allocs/op",
            "value": 42,
            "unit": "allocs/op",
            "extra": "446516 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get",
            "value": 173.1,
            "unit": "ns/op\t      88 B/op\t       3 allocs/op",
            "extra": "6940598 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - ns/op",
            "value": 173.1,
            "unit": "ns/op",
            "extra": "6940598 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - B/op",
            "value": 88,
            "unit": "B/op",
            "extra": "6940598 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "6940598 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set",
            "value": 476.6,
            "unit": "ns/op\t     129 B/op\t       4 allocs/op",
            "extra": "2531917 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - ns/op",
            "value": 476.6,
            "unit": "ns/op",
            "extra": "2531917 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - B/op",
            "value": 129,
            "unit": "B/op",
            "extra": "2531917 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "2531917 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient",
            "value": 78676,
            "unit": "ns/op\t    3387 B/op\t      56 allocs/op",
            "extra": "15225 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - ns/op",
            "value": 78676,
            "unit": "ns/op",
            "extra": "15225 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - B/op",
            "value": 3387,
            "unit": "B/op",
            "extra": "15225 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - allocs/op",
            "value": 56,
            "unit": "allocs/op",
            "extra": "15225 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "9135641fd174ac2d2c76e0143897977b0368505e",
          "message": "chore(deps): Bump recharts from 3.10.0 to 3.10.1 in /web (#255)\n\nBumps [recharts](https://github.com/recharts/recharts) from 3.10.0 to 3.10.1.\n- [Release notes](https://github.com/recharts/recharts/releases)\n- [Changelog](https://github.com/recharts/recharts/blob/main/CHANGELOG.md)\n- [Commits](https://github.com/recharts/recharts/compare/v3.10.0...v3.10.1)\n\n---\nupdated-dependencies:\n- dependency-name: recharts\n  dependency-version: 3.10.1\n  dependency-type: direct:production\n  update-type: version-update:semver-patch\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
          "timestamp": "2026-07-29T08:01:06+01:00",
          "tree_id": "5244f75db7e2e3e5ad35493bac6480a921802a66",
          "url": "https://github.com/rm-hull/dot-block/commit/9135641fd174ac2d2c76e0143897977b0368505e"
        },
        "date": 1785308653924,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDNSDispatcher/CacheHit",
            "value": 3803,
            "unit": "ns/op\t    2346 B/op\t      43 allocs/op",
            "extra": "300084 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - ns/op",
            "value": 3803,
            "unit": "ns/op",
            "extra": "300084 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - B/op",
            "value": 2346,
            "unit": "B/op",
            "extra": "300084 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - allocs/op",
            "value": 43,
            "unit": "allocs/op",
            "extra": "300084 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME",
            "value": 3936,
            "unit": "ns/op\t    2434 B/op\t      44 allocs/op",
            "extra": "291962 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - ns/op",
            "value": 3936,
            "unit": "ns/op",
            "extra": "291962 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - B/op",
            "value": 2434,
            "unit": "B/op",
            "extra": "291962 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "291962 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss",
            "value": 82509,
            "unit": "ns/op\t    6776 B/op\t     116 allocs/op",
            "extra": "14445 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - ns/op",
            "value": 82509,
            "unit": "ns/op",
            "extra": "14445 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - B/op",
            "value": 6776,
            "unit": "B/op",
            "extra": "14445 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - allocs/op",
            "value": 116,
            "unit": "allocs/op",
            "extra": "14445 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked",
            "value": 3456,
            "unit": "ns/op\t    2338 B/op\t      44 allocs/op",
            "extra": "328651 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - ns/op",
            "value": 3456,
            "unit": "ns/op",
            "extra": "328651 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - B/op",
            "value": 2338,
            "unit": "B/op",
            "extra": "328651 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "328651 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE",
            "value": 3632,
            "unit": "ns/op\t    2450 B/op\t      48 allocs/op",
            "extra": "317587 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - ns/op",
            "value": 3632,
            "unit": "ns/op",
            "extra": "317587 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - B/op",
            "value": 2450,
            "unit": "B/op",
            "extra": "317587 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - allocs/op",
            "value": 48,
            "unit": "allocs/op",
            "extra": "317587 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD",
            "value": 3455,
            "unit": "ns/op\t    2162 B/op\t      37 allocs/op",
            "extra": "339116 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - ns/op",
            "value": 3455,
            "unit": "ns/op",
            "extra": "339116 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - B/op",
            "value": 2162,
            "unit": "B/op",
            "extra": "339116 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - allocs/op",
            "value": 37,
            "unit": "allocs/op",
            "extra": "339116 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD",
            "value": 3182,
            "unit": "ns/op\t    2137 B/op\t      36 allocs/op",
            "extra": "374990 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - ns/op",
            "value": 3182,
            "unit": "ns/op",
            "extra": "374990 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - B/op",
            "value": 2137,
            "unit": "B/op",
            "extra": "374990 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - allocs/op",
            "value": 36,
            "unit": "allocs/op",
            "extra": "374990 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions",
            "value": 86170,
            "unit": "ns/op\t    7554 B/op\t     132 allocs/op",
            "extra": "13959 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - ns/op",
            "value": 86170,
            "unit": "ns/op",
            "extra": "13959 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - B/op",
            "value": 7554,
            "unit": "B/op",
            "extra": "13959 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - allocs/op",
            "value": 132,
            "unit": "allocs/op",
            "extra": "13959 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS",
            "value": 4580,
            "unit": "ns/op\t    3746 B/op\t      61 allocs/op",
            "extra": "261766 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - ns/op",
            "value": 4580,
            "unit": "ns/op",
            "extra": "261766 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - B/op",
            "value": 3746,
            "unit": "B/op",
            "extra": "261766 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - allocs/op",
            "value": 61,
            "unit": "allocs/op",
            "extra": "261766 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent",
            "value": 2092,
            "unit": "ns/op\t    2321 B/op\t      42 allocs/op",
            "extra": "545432 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - ns/op",
            "value": 2092,
            "unit": "ns/op",
            "extra": "545432 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - B/op",
            "value": 2321,
            "unit": "B/op",
            "extra": "545432 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - allocs/op",
            "value": 42,
            "unit": "allocs/op",
            "extra": "545432 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get",
            "value": 128.6,
            "unit": "ns/op\t      88 B/op\t       3 allocs/op",
            "extra": "9186250 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - ns/op",
            "value": 128.6,
            "unit": "ns/op",
            "extra": "9186250 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - B/op",
            "value": 88,
            "unit": "B/op",
            "extra": "9186250 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "9186250 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set",
            "value": 288,
            "unit": "ns/op\t     109 B/op\t       4 allocs/op",
            "extra": "4101826 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - ns/op",
            "value": 288,
            "unit": "ns/op",
            "extra": "4101826 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - B/op",
            "value": 109,
            "unit": "B/op",
            "extra": "4101826 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "4101826 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient",
            "value": 63015,
            "unit": "ns/op\t    3387 B/op\t      56 allocs/op",
            "extra": "19108 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - ns/op",
            "value": 63015,
            "unit": "ns/op",
            "extra": "19108 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - B/op",
            "value": 3387,
            "unit": "B/op",
            "extra": "19108 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - allocs/op",
            "value": 56,
            "unit": "allocs/op",
            "extra": "19108 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "rm_hull@yahoo.co.uk",
            "name": "Richard Hull",
            "username": "rm-hull"
          },
          "committer": {
            "email": "rm_hull@yahoo.co.uk",
            "name": "Richard Hull",
            "username": "rm-hull"
          },
          "distinct": true,
          "id": "74679e0d564aefe6e13e0367628dc78f89cfe2bb",
          "message": "chore: updated pnpm lock file",
          "timestamp": "2026-07-29T11:46:05+01:00",
          "tree_id": "67bb5985f11fed0d23d460495720fef826d0b7e4",
          "url": "https://github.com/rm-hull/dot-block/commit/74679e0d564aefe6e13e0367628dc78f89cfe2bb"
        },
        "date": 1785322139287,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDNSDispatcher/CacheHit",
            "value": 2850,
            "unit": "ns/op\t    2346 B/op\t      43 allocs/op",
            "extra": "403455 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - ns/op",
            "value": 2850,
            "unit": "ns/op",
            "extra": "403455 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - B/op",
            "value": 2346,
            "unit": "B/op",
            "extra": "403455 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - allocs/op",
            "value": 43,
            "unit": "allocs/op",
            "extra": "403455 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME",
            "value": 2928,
            "unit": "ns/op\t    2434 B/op\t      44 allocs/op",
            "extra": "406761 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - ns/op",
            "value": 2928,
            "unit": "ns/op",
            "extra": "406761 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - B/op",
            "value": 2434,
            "unit": "B/op",
            "extra": "406761 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "406761 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss",
            "value": 49953,
            "unit": "ns/op\t    6753 B/op\t     116 allocs/op",
            "extra": "23941 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - ns/op",
            "value": 49953,
            "unit": "ns/op",
            "extra": "23941 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - B/op",
            "value": 6753,
            "unit": "B/op",
            "extra": "23941 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - allocs/op",
            "value": 116,
            "unit": "allocs/op",
            "extra": "23941 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked",
            "value": 2569,
            "unit": "ns/op\t    2338 B/op\t      44 allocs/op",
            "extra": "451208 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - ns/op",
            "value": 2569,
            "unit": "ns/op",
            "extra": "451208 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - B/op",
            "value": 2338,
            "unit": "B/op",
            "extra": "451208 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "451208 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE",
            "value": 2686,
            "unit": "ns/op\t    2450 B/op\t      48 allocs/op",
            "extra": "456018 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - ns/op",
            "value": 2686,
            "unit": "ns/op",
            "extra": "456018 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - B/op",
            "value": 2450,
            "unit": "B/op",
            "extra": "456018 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - allocs/op",
            "value": 48,
            "unit": "allocs/op",
            "extra": "456018 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD",
            "value": 2527,
            "unit": "ns/op\t    2161 B/op\t      37 allocs/op",
            "extra": "474327 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - ns/op",
            "value": 2527,
            "unit": "ns/op",
            "extra": "474327 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - B/op",
            "value": 2161,
            "unit": "B/op",
            "extra": "474327 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - allocs/op",
            "value": 37,
            "unit": "allocs/op",
            "extra": "474327 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD",
            "value": 2456,
            "unit": "ns/op\t    2137 B/op\t      36 allocs/op",
            "extra": "488059 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - ns/op",
            "value": 2456,
            "unit": "ns/op",
            "extra": "488059 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - B/op",
            "value": 2137,
            "unit": "B/op",
            "extra": "488059 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - allocs/op",
            "value": 36,
            "unit": "allocs/op",
            "extra": "488059 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions",
            "value": 51276,
            "unit": "ns/op\t    7529 B/op\t     132 allocs/op",
            "extra": "22884 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - ns/op",
            "value": 51276,
            "unit": "ns/op",
            "extra": "22884 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - B/op",
            "value": 7529,
            "unit": "B/op",
            "extra": "22884 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - allocs/op",
            "value": 132,
            "unit": "allocs/op",
            "extra": "22884 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS",
            "value": 3317,
            "unit": "ns/op\t    3719 B/op\t      61 allocs/op",
            "extra": "334026 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - ns/op",
            "value": 3317,
            "unit": "ns/op",
            "extra": "334026 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - B/op",
            "value": 3719,
            "unit": "B/op",
            "extra": "334026 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - allocs/op",
            "value": 61,
            "unit": "allocs/op",
            "extra": "334026 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent",
            "value": 1458,
            "unit": "ns/op\t    2321 B/op\t      42 allocs/op",
            "extra": "746936 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - ns/op",
            "value": 1458,
            "unit": "ns/op",
            "extra": "746936 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - B/op",
            "value": 2321,
            "unit": "B/op",
            "extra": "746936 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - allocs/op",
            "value": 42,
            "unit": "allocs/op",
            "extra": "746936 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get",
            "value": 107.3,
            "unit": "ns/op\t      88 B/op\t       3 allocs/op",
            "extra": "10925708 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - ns/op",
            "value": 107.3,
            "unit": "ns/op",
            "extra": "10925708 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - B/op",
            "value": 88,
            "unit": "B/op",
            "extra": "10925708 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "10925708 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set",
            "value": 286.1,
            "unit": "ns/op\t     122 B/op\t       4 allocs/op",
            "extra": "4242278 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - ns/op",
            "value": 286.1,
            "unit": "ns/op",
            "extra": "4242278 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - B/op",
            "value": 122,
            "unit": "B/op",
            "extra": "4242278 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "4242278 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient",
            "value": 42706,
            "unit": "ns/op\t    3386 B/op\t      56 allocs/op",
            "extra": "27792 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - ns/op",
            "value": 42706,
            "unit": "ns/op",
            "extra": "27792 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - B/op",
            "value": 3386,
            "unit": "B/op",
            "extra": "27792 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - allocs/op",
            "value": 56,
            "unit": "allocs/op",
            "extra": "27792 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "rm_hull@yahoo.co.uk",
            "name": "Richard Hull",
            "username": "rm-hull"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "890b5a870c33a2de092a7ebb54f45819fe645027",
          "message": "feat: include blocklist cause in dns_top_blocked_domains metric (#257)",
          "timestamp": "2026-07-29T21:04:34+01:00",
          "tree_id": "a268cba77e7d27c0e944a8c709ca373e7c9d6b0e",
          "url": "https://github.com/rm-hull/dot-block/commit/890b5a870c33a2de092a7ebb54f45819fe645027"
        },
        "date": 1785355643362,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDNSDispatcher/CacheHit",
            "value": 5030,
            "unit": "ns/op\t    2346 B/op\t      43 allocs/op",
            "extra": "232737 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - ns/op",
            "value": 5030,
            "unit": "ns/op",
            "extra": "232737 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - B/op",
            "value": 2346,
            "unit": "B/op",
            "extra": "232737 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - allocs/op",
            "value": 43,
            "unit": "allocs/op",
            "extra": "232737 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME",
            "value": 5201,
            "unit": "ns/op\t    2434 B/op\t      44 allocs/op",
            "extra": "217995 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - ns/op",
            "value": 5201,
            "unit": "ns/op",
            "extra": "217995 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - B/op",
            "value": 2434,
            "unit": "B/op",
            "extra": "217995 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "217995 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss",
            "value": 110392,
            "unit": "ns/op\t    6806 B/op\t     116 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - ns/op",
            "value": 110392,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - B/op",
            "value": 6806,
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
            "value": 4534,
            "unit": "ns/op\t    2378 B/op\t      45 allocs/op",
            "extra": "260792 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - ns/op",
            "value": 4534,
            "unit": "ns/op",
            "extra": "260792 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - B/op",
            "value": 2378,
            "unit": "B/op",
            "extra": "260792 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - allocs/op",
            "value": 45,
            "unit": "allocs/op",
            "extra": "260792 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE",
            "value": 5159,
            "unit": "ns/op\t    2490 B/op\t      49 allocs/op",
            "extra": "250968 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - ns/op",
            "value": 5159,
            "unit": "ns/op",
            "extra": "250968 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - B/op",
            "value": 2490,
            "unit": "B/op",
            "extra": "250968 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - allocs/op",
            "value": 49,
            "unit": "allocs/op",
            "extra": "250968 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD",
            "value": 4599,
            "unit": "ns/op\t    2162 B/op\t      37 allocs/op",
            "extra": "268884 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - ns/op",
            "value": 4599,
            "unit": "ns/op",
            "extra": "268884 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - B/op",
            "value": 2162,
            "unit": "B/op",
            "extra": "268884 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - allocs/op",
            "value": 37,
            "unit": "allocs/op",
            "extra": "268884 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD",
            "value": 4204,
            "unit": "ns/op\t    2137 B/op\t      36 allocs/op",
            "extra": "266347 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - ns/op",
            "value": 4204,
            "unit": "ns/op",
            "extra": "266347 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - B/op",
            "value": 2137,
            "unit": "B/op",
            "extra": "266347 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - allocs/op",
            "value": 36,
            "unit": "allocs/op",
            "extra": "266347 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions",
            "value": 114797,
            "unit": "ns/op\t    7622 B/op\t     134 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - ns/op",
            "value": 114797,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - B/op",
            "value": 7622,
            "unit": "B/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - allocs/op",
            "value": 134,
            "unit": "allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS",
            "value": 5912,
            "unit": "ns/op\t    3645 B/op\t      61 allocs/op",
            "extra": "203071 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - ns/op",
            "value": 5912,
            "unit": "ns/op",
            "extra": "203071 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - B/op",
            "value": 3645,
            "unit": "B/op",
            "extra": "203071 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - allocs/op",
            "value": 61,
            "unit": "allocs/op",
            "extra": "203071 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent",
            "value": 2644,
            "unit": "ns/op\t    2321 B/op\t      42 allocs/op",
            "extra": "398293 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - ns/op",
            "value": 2644,
            "unit": "ns/op",
            "extra": "398293 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - B/op",
            "value": 2321,
            "unit": "B/op",
            "extra": "398293 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - allocs/op",
            "value": 42,
            "unit": "allocs/op",
            "extra": "398293 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get",
            "value": 163.6,
            "unit": "ns/op\t      88 B/op\t       3 allocs/op",
            "extra": "7277360 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - ns/op",
            "value": 163.6,
            "unit": "ns/op",
            "extra": "7277360 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - B/op",
            "value": 88,
            "unit": "B/op",
            "extra": "7277360 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "7277360 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set",
            "value": 435,
            "unit": "ns/op\t     116 B/op\t       4 allocs/op",
            "extra": "2771889 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - ns/op",
            "value": 435,
            "unit": "ns/op",
            "extra": "2771889 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - B/op",
            "value": 116,
            "unit": "B/op",
            "extra": "2771889 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "2771889 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient",
            "value": 81522,
            "unit": "ns/op\t    3387 B/op\t      56 allocs/op",
            "extra": "14629 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - ns/op",
            "value": 81522,
            "unit": "ns/op",
            "extra": "14629 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - B/op",
            "value": 3387,
            "unit": "B/op",
            "extra": "14629 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - allocs/op",
            "value": 56,
            "unit": "allocs/op",
            "extra": "14629 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "rm_hull@yahoo.co.uk",
            "name": "Richard Hull",
            "username": "rm-hull"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "b5ee9a546aeab3e7d99fd8ad6bb9ab8b8f496a7e",
          "message": "refactor: fetch blocklists asynchronously on startup (#258)\n\n* refactor: fetch blocklists asynchronously on startup\n\n- Run blocklist initial fetch in a background goroutine so the DNS\nserver starts immediately.\n- Add `IsLoaded` and `AllLoaded` methods to track blocklist readiness.\n- Add benchmark and unit tests for blocklist processing and update\nstates.\n- Update integration tests with retry logic to handle asynchronous\nblocklist loading.\n\n* Optimize blocklist loader to reduce allocations and memory usage\n\n* Remove unused IsLoaded and AllLoaded methods\n\n* Refactor blocklist loader to use unified stream and count pattern\n\n* refactor: optimize blocklist loader with streaming and buffering\n\n- Replaced line counting with a fast `io.Reader` buffer scan to estimate\n bloom filter size.\n- Refactored `stream` to accept `io.Reader`, decoupling file I/O from\nparsing logic.\n- Reduced memory overhead by processing blocklists in a single pass.\n\n```mermaid\nsequenceDiagram\n    participant B as BlockList.processFile\n    participant F as File (io.Reader)\n    participant C as countNewlines\n    participant S as stream\n\n    B->>C: Read file to estimate size\n    C->>B: Return line count\n    B->>B: Seek(0, io.SeekStart)\n    B->>S: Stream file with scanner\n    S->>B: Return parsed metadata\n    B->>B: Apply Bloom Filter\n```",
          "timestamp": "2026-07-30T00:07:48+01:00",
          "tree_id": "0257718ad66c7805c71ddebf46b3d1b70293361a",
          "url": "https://github.com/rm-hull/dot-block/commit/b5ee9a546aeab3e7d99fd8ad6bb9ab8b8f496a7e"
        },
        "date": 1785366641556,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDNSDispatcher/CacheHit",
            "value": 3887,
            "unit": "ns/op\t    2346 B/op\t      43 allocs/op",
            "extra": "297200 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - ns/op",
            "value": 3887,
            "unit": "ns/op",
            "extra": "297200 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - B/op",
            "value": 2346,
            "unit": "B/op",
            "extra": "297200 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - allocs/op",
            "value": 43,
            "unit": "allocs/op",
            "extra": "297200 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME",
            "value": 3928,
            "unit": "ns/op\t    2434 B/op\t      44 allocs/op",
            "extra": "305887 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - ns/op",
            "value": 3928,
            "unit": "ns/op",
            "extra": "305887 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - B/op",
            "value": 2434,
            "unit": "B/op",
            "extra": "305887 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "305887 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss",
            "value": 49593,
            "unit": "ns/op\t    6750 B/op\t     116 allocs/op",
            "extra": "25435 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - ns/op",
            "value": 49593,
            "unit": "ns/op",
            "extra": "25435 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - B/op",
            "value": 6750,
            "unit": "B/op",
            "extra": "25435 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - allocs/op",
            "value": 116,
            "unit": "allocs/op",
            "extra": "25435 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked",
            "value": 3527,
            "unit": "ns/op\t    2378 B/op\t      45 allocs/op",
            "extra": "322724 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - ns/op",
            "value": 3527,
            "unit": "ns/op",
            "extra": "322724 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - B/op",
            "value": 2378,
            "unit": "B/op",
            "extra": "322724 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - allocs/op",
            "value": 45,
            "unit": "allocs/op",
            "extra": "322724 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE",
            "value": 3637,
            "unit": "ns/op\t    2490 B/op\t      49 allocs/op",
            "extra": "329354 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - ns/op",
            "value": 3637,
            "unit": "ns/op",
            "extra": "329354 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - B/op",
            "value": 2490,
            "unit": "B/op",
            "extra": "329354 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - allocs/op",
            "value": 49,
            "unit": "allocs/op",
            "extra": "329354 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD",
            "value": 3461,
            "unit": "ns/op\t    2162 B/op\t      37 allocs/op",
            "extra": "342706 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - ns/op",
            "value": 3461,
            "unit": "ns/op",
            "extra": "342706 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - B/op",
            "value": 2162,
            "unit": "B/op",
            "extra": "342706 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - allocs/op",
            "value": 37,
            "unit": "allocs/op",
            "extra": "342706 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD",
            "value": 3172,
            "unit": "ns/op\t    2137 B/op\t      36 allocs/op",
            "extra": "368094 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - ns/op",
            "value": 3172,
            "unit": "ns/op",
            "extra": "368094 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - B/op",
            "value": 2137,
            "unit": "B/op",
            "extra": "368094 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - allocs/op",
            "value": 36,
            "unit": "allocs/op",
            "extra": "368094 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions",
            "value": 53872,
            "unit": "ns/op\t    7569 B/op\t     133 allocs/op",
            "extra": "23188 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - ns/op",
            "value": 53872,
            "unit": "ns/op",
            "extra": "23188 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - B/op",
            "value": 7569,
            "unit": "B/op",
            "extra": "23188 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - allocs/op",
            "value": 133,
            "unit": "allocs/op",
            "extra": "23188 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS",
            "value": 4213,
            "unit": "ns/op\t    3617 B/op\t      60 allocs/op",
            "extra": "250671 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - ns/op",
            "value": 4213,
            "unit": "ns/op",
            "extra": "250671 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - B/op",
            "value": 3617,
            "unit": "B/op",
            "extra": "250671 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "250671 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent",
            "value": 2235,
            "unit": "ns/op\t    2321 B/op\t      42 allocs/op",
            "extra": "542913 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - ns/op",
            "value": 2235,
            "unit": "ns/op",
            "extra": "542913 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - B/op",
            "value": 2321,
            "unit": "B/op",
            "extra": "542913 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - allocs/op",
            "value": 42,
            "unit": "allocs/op",
            "extra": "542913 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get",
            "value": 142.4,
            "unit": "ns/op\t      88 B/op\t       3 allocs/op",
            "extra": "8287207 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - ns/op",
            "value": 142.4,
            "unit": "ns/op",
            "extra": "8287207 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - B/op",
            "value": 88,
            "unit": "B/op",
            "extra": "8287207 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "8287207 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set",
            "value": 481.9,
            "unit": "ns/op\t     122 B/op\t       4 allocs/op",
            "extra": "2525846 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - ns/op",
            "value": 481.9,
            "unit": "ns/op",
            "extra": "2525846 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - B/op",
            "value": 122,
            "unit": "B/op",
            "extra": "2525846 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "2525846 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient",
            "value": 44365,
            "unit": "ns/op\t    3387 B/op\t      56 allocs/op",
            "extra": "26935 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - ns/op",
            "value": 44365,
            "unit": "ns/op",
            "extra": "26935 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - B/op",
            "value": 3387,
            "unit": "B/op",
            "extra": "26935 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - allocs/op",
            "value": 56,
            "unit": "allocs/op",
            "extra": "26935 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "rm_hull@yahoo.co.uk",
            "name": "Richard Hull",
            "username": "rm-hull"
          },
          "committer": {
            "email": "rm_hull@yahoo.co.uk",
            "name": "Richard Hull",
            "username": "rm-hull"
          },
          "distinct": true,
          "id": "eca115f0334efd43a60d27c8359686444d2658a2",
          "message": "style(web): adjust padding and remove border on EventPage aggregate\n\nUpdate `HStack` container spacing within the collapsible aggregates\nsection\nto improve visual alignment with surrounding UI elements.",
          "timestamp": "2026-07-30T18:51:06+01:00",
          "tree_id": "1eed3e83c538d2202408d548ec6903d5402133d5",
          "url": "https://github.com/rm-hull/dot-block/commit/eca115f0334efd43a60d27c8359686444d2658a2"
        },
        "date": 1785434172732,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDNSDispatcher/CacheHit",
            "value": 3401,
            "unit": "ns/op\t    2346 B/op\t      43 allocs/op",
            "extra": "350944 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - ns/op",
            "value": 3401,
            "unit": "ns/op",
            "extra": "350944 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - B/op",
            "value": 2346,
            "unit": "B/op",
            "extra": "350944 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - allocs/op",
            "value": 43,
            "unit": "allocs/op",
            "extra": "350944 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME",
            "value": 3492,
            "unit": "ns/op\t    2434 B/op\t      44 allocs/op",
            "extra": "348050 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - ns/op",
            "value": 3492,
            "unit": "ns/op",
            "extra": "348050 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - B/op",
            "value": 2434,
            "unit": "B/op",
            "extra": "348050 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "348050 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss",
            "value": 43075,
            "unit": "ns/op\t    6746 B/op\t     116 allocs/op",
            "extra": "27834 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - ns/op",
            "value": 43075,
            "unit": "ns/op",
            "extra": "27834 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - B/op",
            "value": 6746,
            "unit": "B/op",
            "extra": "27834 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - allocs/op",
            "value": 116,
            "unit": "allocs/op",
            "extra": "27834 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked",
            "value": 2948,
            "unit": "ns/op\t    2378 B/op\t      45 allocs/op",
            "extra": "408103 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - ns/op",
            "value": 2948,
            "unit": "ns/op",
            "extra": "408103 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - B/op",
            "value": 2378,
            "unit": "B/op",
            "extra": "408103 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - allocs/op",
            "value": 45,
            "unit": "allocs/op",
            "extra": "408103 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE",
            "value": 3050,
            "unit": "ns/op\t    2490 B/op\t      49 allocs/op",
            "extra": "407324 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - ns/op",
            "value": 3050,
            "unit": "ns/op",
            "extra": "407324 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - B/op",
            "value": 2490,
            "unit": "B/op",
            "extra": "407324 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - allocs/op",
            "value": 49,
            "unit": "allocs/op",
            "extra": "407324 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD",
            "value": 2831,
            "unit": "ns/op\t    2161 B/op\t      37 allocs/op",
            "extra": "421444 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - ns/op",
            "value": 2831,
            "unit": "ns/op",
            "extra": "421444 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - B/op",
            "value": 2161,
            "unit": "B/op",
            "extra": "421444 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - allocs/op",
            "value": 37,
            "unit": "allocs/op",
            "extra": "421444 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD",
            "value": 2721,
            "unit": "ns/op\t    2137 B/op\t      36 allocs/op",
            "extra": "447288 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - ns/op",
            "value": 2721,
            "unit": "ns/op",
            "extra": "447288 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - B/op",
            "value": 2137,
            "unit": "B/op",
            "extra": "447288 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - allocs/op",
            "value": 36,
            "unit": "allocs/op",
            "extra": "447288 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions",
            "value": 44035,
            "unit": "ns/op\t    7563 B/op\t     133 allocs/op",
            "extra": "27014 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - ns/op",
            "value": 44035,
            "unit": "ns/op",
            "extra": "27014 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - B/op",
            "value": 7563,
            "unit": "B/op",
            "extra": "27014 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - allocs/op",
            "value": 133,
            "unit": "allocs/op",
            "extra": "27014 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS",
            "value": 3433,
            "unit": "ns/op\t    3615 B/op\t      60 allocs/op",
            "extra": "312442 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - ns/op",
            "value": 3433,
            "unit": "ns/op",
            "extra": "312442 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - B/op",
            "value": 3615,
            "unit": "B/op",
            "extra": "312442 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "312442 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent",
            "value": 1848,
            "unit": "ns/op\t    2321 B/op\t      42 allocs/op",
            "extra": "566836 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - ns/op",
            "value": 1848,
            "unit": "ns/op",
            "extra": "566836 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - B/op",
            "value": 2321,
            "unit": "B/op",
            "extra": "566836 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - allocs/op",
            "value": 42,
            "unit": "allocs/op",
            "extra": "566836 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get",
            "value": 114.7,
            "unit": "ns/op\t      88 B/op\t       3 allocs/op",
            "extra": "10444789 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - ns/op",
            "value": 114.7,
            "unit": "ns/op",
            "extra": "10444789 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - B/op",
            "value": 88,
            "unit": "B/op",
            "extra": "10444789 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "10444789 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set",
            "value": 453.6,
            "unit": "ns/op\t     122 B/op\t       4 allocs/op",
            "extra": "2471317 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - ns/op",
            "value": 453.6,
            "unit": "ns/op",
            "extra": "2471317 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - B/op",
            "value": 122,
            "unit": "B/op",
            "extra": "2471317 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "2471317 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient",
            "value": 37052,
            "unit": "ns/op\t    3386 B/op\t      56 allocs/op",
            "extra": "32809 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - ns/op",
            "value": 37052,
            "unit": "ns/op",
            "extra": "32809 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - B/op",
            "value": 3386,
            "unit": "B/op",
            "extra": "32809 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - allocs/op",
            "value": 56,
            "unit": "allocs/op",
            "extra": "32809 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "rm_hull@yahoo.co.uk",
            "name": "Richard Hull",
            "username": "rm-hull"
          },
          "committer": {
            "email": "rm_hull@yahoo.co.uk",
            "name": "Richard Hull",
            "username": "rm-hull"
          },
          "distinct": true,
          "id": "fd029f514103286f8a8006ec733bcfc4faa9962f",
          "message": "fix(http): add SSE heartbeat to prevent connection timeout\n\nAdd a 15-second ticker to send SSE comment pings, preventing proxy and\nload balancer timeouts on idle real-time request streams.",
          "timestamp": "2026-07-30T19:01:24+01:00",
          "tree_id": "c246dcbfedfb8753386e507695ad6b4f8cb8fc12",
          "url": "https://github.com/rm-hull/dot-block/commit/fd029f514103286f8a8006ec733bcfc4faa9962f"
        },
        "date": 1785434808743,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDNSDispatcher/CacheHit",
            "value": 4383,
            "unit": "ns/op\t    2346 B/op\t      43 allocs/op",
            "extra": "258951 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - ns/op",
            "value": 4383,
            "unit": "ns/op",
            "extra": "258951 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - B/op",
            "value": 2346,
            "unit": "B/op",
            "extra": "258951 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - allocs/op",
            "value": 43,
            "unit": "allocs/op",
            "extra": "258951 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME",
            "value": 4417,
            "unit": "ns/op\t    2434 B/op\t      44 allocs/op",
            "extra": "270439 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - ns/op",
            "value": 4417,
            "unit": "ns/op",
            "extra": "270439 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - B/op",
            "value": 2434,
            "unit": "B/op",
            "extra": "270439 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "270439 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss",
            "value": 60172,
            "unit": "ns/op\t    6759 B/op\t     116 allocs/op",
            "extra": "19941 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - ns/op",
            "value": 60172,
            "unit": "ns/op",
            "extra": "19941 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - B/op",
            "value": 6759,
            "unit": "B/op",
            "extra": "19941 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - allocs/op",
            "value": 116,
            "unit": "allocs/op",
            "extra": "19941 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked",
            "value": 3957,
            "unit": "ns/op\t    2378 B/op\t      45 allocs/op",
            "extra": "279262 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - ns/op",
            "value": 3957,
            "unit": "ns/op",
            "extra": "279262 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - B/op",
            "value": 2378,
            "unit": "B/op",
            "extra": "279262 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - allocs/op",
            "value": 45,
            "unit": "allocs/op",
            "extra": "279262 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE",
            "value": 4073,
            "unit": "ns/op\t    2490 B/op\t      49 allocs/op",
            "extra": "274820 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - ns/op",
            "value": 4073,
            "unit": "ns/op",
            "extra": "274820 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - B/op",
            "value": 2490,
            "unit": "B/op",
            "extra": "274820 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - allocs/op",
            "value": 49,
            "unit": "allocs/op",
            "extra": "274820 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD",
            "value": 4033,
            "unit": "ns/op\t    2162 B/op\t      37 allocs/op",
            "extra": "303788 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - ns/op",
            "value": 4033,
            "unit": "ns/op",
            "extra": "303788 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - B/op",
            "value": 2162,
            "unit": "B/op",
            "extra": "303788 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - allocs/op",
            "value": 37,
            "unit": "allocs/op",
            "extra": "303788 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD",
            "value": 3621,
            "unit": "ns/op\t    2137 B/op\t      36 allocs/op",
            "extra": "307045 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - ns/op",
            "value": 3621,
            "unit": "ns/op",
            "extra": "307045 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - B/op",
            "value": 2137,
            "unit": "B/op",
            "extra": "307045 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - allocs/op",
            "value": 36,
            "unit": "allocs/op",
            "extra": "307045 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions",
            "value": 56690,
            "unit": "ns/op\t    7572 B/op\t     133 allocs/op",
            "extra": "20794 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - ns/op",
            "value": 56690,
            "unit": "ns/op",
            "extra": "20794 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - B/op",
            "value": 7572,
            "unit": "B/op",
            "extra": "20794 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - allocs/op",
            "value": 133,
            "unit": "allocs/op",
            "extra": "20794 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS",
            "value": 4972,
            "unit": "ns/op\t    3562 B/op\t      60 allocs/op",
            "extra": "215791 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - ns/op",
            "value": 4972,
            "unit": "ns/op",
            "extra": "215791 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - B/op",
            "value": 3562,
            "unit": "B/op",
            "extra": "215791 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "215791 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent",
            "value": 2473,
            "unit": "ns/op\t    2321 B/op\t      42 allocs/op",
            "extra": "422287 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - ns/op",
            "value": 2473,
            "unit": "ns/op",
            "extra": "422287 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - B/op",
            "value": 2321,
            "unit": "B/op",
            "extra": "422287 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - allocs/op",
            "value": 42,
            "unit": "allocs/op",
            "extra": "422287 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get",
            "value": 157.6,
            "unit": "ns/op\t      88 B/op\t       3 allocs/op",
            "extra": "7701465 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - ns/op",
            "value": 157.6,
            "unit": "ns/op",
            "extra": "7701465 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - B/op",
            "value": 88,
            "unit": "B/op",
            "extra": "7701465 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "7701465 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set",
            "value": 575.3,
            "unit": "ns/op\t     137 B/op\t       4 allocs/op",
            "extra": "2099040 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - ns/op",
            "value": 575.3,
            "unit": "ns/op",
            "extra": "2099040 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - B/op",
            "value": 137,
            "unit": "B/op",
            "extra": "2099040 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "2099040 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient",
            "value": 50723,
            "unit": "ns/op\t    3387 B/op\t      56 allocs/op",
            "extra": "23284 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - ns/op",
            "value": 50723,
            "unit": "ns/op",
            "extra": "23284 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - B/op",
            "value": 3387,
            "unit": "B/op",
            "extra": "23284 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - allocs/op",
            "value": 56,
            "unit": "allocs/op",
            "extra": "23284 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "rm_hull@yahoo.co.uk",
            "name": "Richard Hull",
            "username": "rm-hull"
          },
          "committer": {
            "email": "rm_hull@yahoo.co.uk",
            "name": "Richard Hull",
            "username": "rm-hull"
          },
          "distinct": true,
          "id": "134a6890f9bb739acd5a7d060ac0b464dfcfc2c3",
          "message": "feat(web): add toast notification for event stream state changes\n\nNotify users when the event stream is paused or resumed, and style\ntoast components with blue accent styling and icons.",
          "timestamp": "2026-07-30T22:40:18+01:00",
          "tree_id": "f55c703ebfe5743f76ab01c70241e715f662af69",
          "url": "https://github.com/rm-hull/dot-block/commit/134a6890f9bb739acd5a7d060ac0b464dfcfc2c3"
        },
        "date": 1785448185892,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDNSDispatcher/CacheHit",
            "value": 5031,
            "unit": "ns/op\t    2346 B/op\t      43 allocs/op",
            "extra": "226965 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - ns/op",
            "value": 5031,
            "unit": "ns/op",
            "extra": "226965 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - B/op",
            "value": 2346,
            "unit": "B/op",
            "extra": "226965 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - allocs/op",
            "value": 43,
            "unit": "allocs/op",
            "extra": "226965 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME",
            "value": 5158,
            "unit": "ns/op\t    2434 B/op\t      44 allocs/op",
            "extra": "238496 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - ns/op",
            "value": 5158,
            "unit": "ns/op",
            "extra": "238496 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - B/op",
            "value": 2434,
            "unit": "B/op",
            "extra": "238496 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "238496 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss",
            "value": 109809,
            "unit": "ns/op\t    6806 B/op\t     116 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - ns/op",
            "value": 109809,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - B/op",
            "value": 6806,
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
            "value": 4598,
            "unit": "ns/op\t    2378 B/op\t      45 allocs/op",
            "extra": "265558 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - ns/op",
            "value": 4598,
            "unit": "ns/op",
            "extra": "265558 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - B/op",
            "value": 2378,
            "unit": "B/op",
            "extra": "265558 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - allocs/op",
            "value": 45,
            "unit": "allocs/op",
            "extra": "265558 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE",
            "value": 4853,
            "unit": "ns/op\t    2490 B/op\t      49 allocs/op",
            "extra": "237624 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - ns/op",
            "value": 4853,
            "unit": "ns/op",
            "extra": "237624 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - B/op",
            "value": 2490,
            "unit": "B/op",
            "extra": "237624 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - allocs/op",
            "value": 49,
            "unit": "allocs/op",
            "extra": "237624 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD",
            "value": 4619,
            "unit": "ns/op\t    2162 B/op\t      37 allocs/op",
            "extra": "261604 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - ns/op",
            "value": 4619,
            "unit": "ns/op",
            "extra": "261604 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - B/op",
            "value": 2162,
            "unit": "B/op",
            "extra": "261604 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - allocs/op",
            "value": 37,
            "unit": "allocs/op",
            "extra": "261604 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD",
            "value": 4592,
            "unit": "ns/op\t    2137 B/op\t      36 allocs/op",
            "extra": "222517 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - ns/op",
            "value": 4592,
            "unit": "ns/op",
            "extra": "222517 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - B/op",
            "value": 2137,
            "unit": "B/op",
            "extra": "222517 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - allocs/op",
            "value": 36,
            "unit": "allocs/op",
            "extra": "222517 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions",
            "value": 116468,
            "unit": "ns/op\t    7623 B/op\t     134 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - ns/op",
            "value": 116468,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - B/op",
            "value": 7623,
            "unit": "B/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - allocs/op",
            "value": 134,
            "unit": "allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS",
            "value": 5649,
            "unit": "ns/op\t    3650 B/op\t      61 allocs/op",
            "extra": "201706 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - ns/op",
            "value": 5649,
            "unit": "ns/op",
            "extra": "201706 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - B/op",
            "value": 3650,
            "unit": "B/op",
            "extra": "201706 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - allocs/op",
            "value": 61,
            "unit": "allocs/op",
            "extra": "201706 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent",
            "value": 2666,
            "unit": "ns/op\t    2321 B/op\t      42 allocs/op",
            "extra": "427537 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - ns/op",
            "value": 2666,
            "unit": "ns/op",
            "extra": "427537 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - B/op",
            "value": 2321,
            "unit": "B/op",
            "extra": "427537 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - allocs/op",
            "value": 42,
            "unit": "allocs/op",
            "extra": "427537 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get",
            "value": 164.2,
            "unit": "ns/op\t      88 B/op\t       3 allocs/op",
            "extra": "7300248 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - ns/op",
            "value": 164.2,
            "unit": "ns/op",
            "extra": "7300248 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - B/op",
            "value": 88,
            "unit": "B/op",
            "extra": "7300248 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "7300248 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set",
            "value": 476.3,
            "unit": "ns/op\t     130 B/op\t       4 allocs/op",
            "extra": "2505661 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - ns/op",
            "value": 476.3,
            "unit": "ns/op",
            "extra": "2505661 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - B/op",
            "value": 130,
            "unit": "B/op",
            "extra": "2505661 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "2505661 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient",
            "value": 81696,
            "unit": "ns/op\t    3387 B/op\t      56 allocs/op",
            "extra": "14721 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - ns/op",
            "value": 81696,
            "unit": "ns/op",
            "extra": "14721 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - B/op",
            "value": 3387,
            "unit": "B/op",
            "extra": "14721 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - allocs/op",
            "value": 56,
            "unit": "allocs/op",
            "extra": "14721 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "rm_hull@yahoo.co.uk",
            "name": "Richard Hull",
            "username": "rm-hull"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "d720755d69d493d0f3c5e313c3532dd81dbf3867",
          "message": "fix: cache negative DNS responses (NODATA and NXDOMAIN) to prevent repeated upstream queries (#259)\n\n* fix(forwarder): support negative caching for NXDOMAIN and NODATA\n\nImplement negative caching in the DNS dispatcher to cache `NXDOMAIN`\n(storing the SOA record as a marker) and `NODATA` (empty answer slice\nfor `NOERROR`) responses, preventing repeated upstream queries for\nnon-existent domains and records.\n\n* test(forwarder): fix race conditions in dispatcher tests\n\nEnable the race detector in test documentation and use atomic operations\nfor upstream call counters in concurrent dispatcher cache tests.",
          "timestamp": "2026-07-31T00:42:09+01:00",
          "tree_id": "3ecf8a0c041d3487c8f27ea2fdb097e09a4182ac",
          "url": "https://github.com/rm-hull/dot-block/commit/d720755d69d493d0f3c5e313c3532dd81dbf3867"
        },
        "date": 1785455088638,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDNSDispatcher/CacheHit",
            "value": 5367,
            "unit": "ns/op\t    2346 B/op\t      43 allocs/op",
            "extra": "220537 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - ns/op",
            "value": 5367,
            "unit": "ns/op",
            "extra": "220537 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - B/op",
            "value": 2346,
            "unit": "B/op",
            "extra": "220537 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - allocs/op",
            "value": 43,
            "unit": "allocs/op",
            "extra": "220537 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME",
            "value": 5523,
            "unit": "ns/op\t    2434 B/op\t      44 allocs/op",
            "extra": "215271 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - ns/op",
            "value": 5523,
            "unit": "ns/op",
            "extra": "215271 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - B/op",
            "value": 2434,
            "unit": "B/op",
            "extra": "215271 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "215271 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss",
            "value": 112637,
            "unit": "ns/op\t    6806 B/op\t     116 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - ns/op",
            "value": 112637,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - B/op",
            "value": 6806,
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
            "value": 4933,
            "unit": "ns/op\t    2378 B/op\t      45 allocs/op",
            "extra": "239954 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - ns/op",
            "value": 4933,
            "unit": "ns/op",
            "extra": "239954 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - B/op",
            "value": 2378,
            "unit": "B/op",
            "extra": "239954 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - allocs/op",
            "value": 45,
            "unit": "allocs/op",
            "extra": "239954 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE",
            "value": 5463,
            "unit": "ns/op\t    2490 B/op\t      49 allocs/op",
            "extra": "231238 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - ns/op",
            "value": 5463,
            "unit": "ns/op",
            "extra": "231238 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - B/op",
            "value": 2490,
            "unit": "B/op",
            "extra": "231238 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - allocs/op",
            "value": 49,
            "unit": "allocs/op",
            "extra": "231238 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD",
            "value": 5131,
            "unit": "ns/op\t    2162 B/op\t      37 allocs/op",
            "extra": "211584 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - ns/op",
            "value": 5131,
            "unit": "ns/op",
            "extra": "211584 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - B/op",
            "value": 2162,
            "unit": "B/op",
            "extra": "211584 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - allocs/op",
            "value": 37,
            "unit": "allocs/op",
            "extra": "211584 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD",
            "value": 4473,
            "unit": "ns/op\t    2138 B/op\t      36 allocs/op",
            "extra": "262218 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - ns/op",
            "value": 4473,
            "unit": "ns/op",
            "extra": "262218 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - B/op",
            "value": 2138,
            "unit": "B/op",
            "extra": "262218 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - allocs/op",
            "value": 36,
            "unit": "allocs/op",
            "extra": "262218 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions",
            "value": 116812,
            "unit": "ns/op\t    7627 B/op\t     134 allocs/op",
            "extra": "9442 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - ns/op",
            "value": 116812,
            "unit": "ns/op",
            "extra": "9442 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - B/op",
            "value": 7627,
            "unit": "B/op",
            "extra": "9442 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - allocs/op",
            "value": 134,
            "unit": "allocs/op",
            "extra": "9442 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS",
            "value": 6149,
            "unit": "ns/op\t    3690 B/op\t      61 allocs/op",
            "extra": "177574 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - ns/op",
            "value": 6149,
            "unit": "ns/op",
            "extra": "177574 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - B/op",
            "value": 3690,
            "unit": "B/op",
            "extra": "177574 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - allocs/op",
            "value": 61,
            "unit": "allocs/op",
            "extra": "177574 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent",
            "value": 2815,
            "unit": "ns/op\t    2321 B/op\t      42 allocs/op",
            "extra": "425626 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - ns/op",
            "value": 2815,
            "unit": "ns/op",
            "extra": "425626 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - B/op",
            "value": 2321,
            "unit": "B/op",
            "extra": "425626 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - allocs/op",
            "value": 42,
            "unit": "allocs/op",
            "extra": "425626 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get",
            "value": 174.8,
            "unit": "ns/op\t      88 B/op\t       3 allocs/op",
            "extra": "6595630 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - ns/op",
            "value": 174.8,
            "unit": "ns/op",
            "extra": "6595630 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - B/op",
            "value": 88,
            "unit": "B/op",
            "extra": "6595630 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "6595630 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set",
            "value": 485.6,
            "unit": "ns/op\t     124 B/op\t       4 allocs/op",
            "extra": "2445414 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - ns/op",
            "value": 485.6,
            "unit": "ns/op",
            "extra": "2445414 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - B/op",
            "value": 124,
            "unit": "B/op",
            "extra": "2445414 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "2445414 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient",
            "value": 80257,
            "unit": "ns/op\t    3386 B/op\t      56 allocs/op",
            "extra": "14817 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - ns/op",
            "value": 80257,
            "unit": "ns/op",
            "extra": "14817 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - B/op",
            "value": 3386,
            "unit": "B/op",
            "extra": "14817 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - allocs/op",
            "value": 56,
            "unit": "allocs/op",
            "extra": "14817 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "rm_hull@yahoo.co.uk",
            "name": "Richard Hull",
            "username": "rm-hull"
          },
          "committer": {
            "email": "rm_hull@yahoo.co.uk",
            "name": "Richard Hull",
            "username": "rm-hull"
          },
          "distinct": true,
          "id": "18c9c871109c068b058cc6b49213d061a7c04e46",
          "message": "docs(web): add filesystem access restriction rule to AGENTS.md\n\nRestrict agent operations strictly to the working repository directory\nand prohibit access to the root partition (`/`).",
          "timestamp": "2026-07-31T00:47:37+01:00",
          "tree_id": "b8d54377d6d3a1d0c86a502616f039806af2e3cb",
          "url": "https://github.com/rm-hull/dot-block/commit/18c9c871109c068b058cc6b49213d061a7c04e46"
        },
        "date": 1785455412652,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDNSDispatcher/CacheHit",
            "value": 5003,
            "unit": "ns/op\t    2346 B/op\t      43 allocs/op",
            "extra": "242592 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - ns/op",
            "value": 5003,
            "unit": "ns/op",
            "extra": "242592 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - B/op",
            "value": 2346,
            "unit": "B/op",
            "extra": "242592 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - allocs/op",
            "value": 43,
            "unit": "allocs/op",
            "extra": "242592 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME",
            "value": 5051,
            "unit": "ns/op\t    2434 B/op\t      44 allocs/op",
            "extra": "227785 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - ns/op",
            "value": 5051,
            "unit": "ns/op",
            "extra": "227785 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - B/op",
            "value": 2434,
            "unit": "B/op",
            "extra": "227785 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "227785 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss",
            "value": 114313,
            "unit": "ns/op\t    6809 B/op\t     116 allocs/op",
            "extra": "9627 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - ns/op",
            "value": 114313,
            "unit": "ns/op",
            "extra": "9627 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - B/op",
            "value": 6809,
            "unit": "B/op",
            "extra": "9627 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - allocs/op",
            "value": 116,
            "unit": "allocs/op",
            "extra": "9627 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked",
            "value": 4990,
            "unit": "ns/op\t    2378 B/op\t      45 allocs/op",
            "extra": "224046 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - ns/op",
            "value": 4990,
            "unit": "ns/op",
            "extra": "224046 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - B/op",
            "value": 2378,
            "unit": "B/op",
            "extra": "224046 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - allocs/op",
            "value": 45,
            "unit": "allocs/op",
            "extra": "224046 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE",
            "value": 4882,
            "unit": "ns/op\t    2490 B/op\t      49 allocs/op",
            "extra": "245932 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - ns/op",
            "value": 4882,
            "unit": "ns/op",
            "extra": "245932 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - B/op",
            "value": 2490,
            "unit": "B/op",
            "extra": "245932 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - allocs/op",
            "value": 49,
            "unit": "allocs/op",
            "extra": "245932 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD",
            "value": 4388,
            "unit": "ns/op\t    2161 B/op\t      37 allocs/op",
            "extra": "265215 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - ns/op",
            "value": 4388,
            "unit": "ns/op",
            "extra": "265215 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - B/op",
            "value": 2161,
            "unit": "B/op",
            "extra": "265215 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - allocs/op",
            "value": 37,
            "unit": "allocs/op",
            "extra": "265215 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD",
            "value": 4127,
            "unit": "ns/op\t    2137 B/op\t      36 allocs/op",
            "extra": "278302 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - ns/op",
            "value": 4127,
            "unit": "ns/op",
            "extra": "278302 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - B/op",
            "value": 2137,
            "unit": "B/op",
            "extra": "278302 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - allocs/op",
            "value": 36,
            "unit": "allocs/op",
            "extra": "278302 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions",
            "value": 116395,
            "unit": "ns/op\t    7621 B/op\t     134 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - ns/op",
            "value": 116395,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - B/op",
            "value": 7621,
            "unit": "B/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - allocs/op",
            "value": 134,
            "unit": "allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS",
            "value": 5821,
            "unit": "ns/op\t    3671 B/op\t      61 allocs/op",
            "extra": "196677 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - ns/op",
            "value": 5821,
            "unit": "ns/op",
            "extra": "196677 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - B/op",
            "value": 3671,
            "unit": "B/op",
            "extra": "196677 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - allocs/op",
            "value": 61,
            "unit": "allocs/op",
            "extra": "196677 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent",
            "value": 2730,
            "unit": "ns/op\t    2321 B/op\t      42 allocs/op",
            "extra": "400501 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - ns/op",
            "value": 2730,
            "unit": "ns/op",
            "extra": "400501 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - B/op",
            "value": 2321,
            "unit": "B/op",
            "extra": "400501 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - allocs/op",
            "value": 42,
            "unit": "allocs/op",
            "extra": "400501 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get",
            "value": 166.7,
            "unit": "ns/op\t      88 B/op\t       3 allocs/op",
            "extra": "7095789 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - ns/op",
            "value": 166.7,
            "unit": "ns/op",
            "extra": "7095789 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - B/op",
            "value": 88,
            "unit": "B/op",
            "extra": "7095789 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "7095789 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set",
            "value": 481,
            "unit": "ns/op\t     125 B/op\t       4 allocs/op",
            "extra": "2494200 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - ns/op",
            "value": 481,
            "unit": "ns/op",
            "extra": "2494200 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - B/op",
            "value": 125,
            "unit": "B/op",
            "extra": "2494200 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "2494200 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient",
            "value": 91274,
            "unit": "ns/op\t    3386 B/op\t      56 allocs/op",
            "extra": "13183 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - ns/op",
            "value": 91274,
            "unit": "ns/op",
            "extra": "13183 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - B/op",
            "value": 3386,
            "unit": "B/op",
            "extra": "13183 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - allocs/op",
            "value": 56,
            "unit": "allocs/op",
            "extra": "13183 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "rm_hull@yahoo.co.uk",
            "name": "Richard Hull",
            "username": "rm-hull"
          },
          "committer": {
            "email": "rm_hull@yahoo.co.uk",
            "name": "Richard Hull",
            "username": "rm-hull"
          },
          "distinct": true,
          "id": "ebac3f4edaee27a05a8a81e02185b4be8cecce4e",
          "message": "feat(web): display answer count in event table\n\nUpdate `DnsEvent` interface and `EventTable` component to render the\nnumber of DNS answers received for each query.",
          "timestamp": "2026-07-31T00:56:51+01:00",
          "tree_id": "9cac42c7582004401a1b633a4a3e1cce91ab9048",
          "url": "https://github.com/rm-hull/dot-block/commit/ebac3f4edaee27a05a8a81e02185b4be8cecce4e"
        },
        "date": 1785455991635,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDNSDispatcher/CacheHit",
            "value": 5087,
            "unit": "ns/op\t    2346 B/op\t      43 allocs/op",
            "extra": "224407 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - ns/op",
            "value": 5087,
            "unit": "ns/op",
            "extra": "224407 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - B/op",
            "value": 2346,
            "unit": "B/op",
            "extra": "224407 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - allocs/op",
            "value": 43,
            "unit": "allocs/op",
            "extra": "224407 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME",
            "value": 5996,
            "unit": "ns/op\t    2434 B/op\t      44 allocs/op",
            "extra": "182581 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - ns/op",
            "value": 5996,
            "unit": "ns/op",
            "extra": "182581 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - B/op",
            "value": 2434,
            "unit": "B/op",
            "extra": "182581 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "182581 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss",
            "value": 118455,
            "unit": "ns/op\t    6805 B/op\t     116 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - ns/op",
            "value": 118455,
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
            "value": 4853,
            "unit": "ns/op\t    2378 B/op\t      45 allocs/op",
            "extra": "242216 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - ns/op",
            "value": 4853,
            "unit": "ns/op",
            "extra": "242216 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - B/op",
            "value": 2378,
            "unit": "B/op",
            "extra": "242216 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - allocs/op",
            "value": 45,
            "unit": "allocs/op",
            "extra": "242216 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE",
            "value": 5008,
            "unit": "ns/op\t    2490 B/op\t      49 allocs/op",
            "extra": "215013 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - ns/op",
            "value": 5008,
            "unit": "ns/op",
            "extra": "215013 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - B/op",
            "value": 2490,
            "unit": "B/op",
            "extra": "215013 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - allocs/op",
            "value": 49,
            "unit": "allocs/op",
            "extra": "215013 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD",
            "value": 4614,
            "unit": "ns/op\t    2162 B/op\t      37 allocs/op",
            "extra": "259029 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - ns/op",
            "value": 4614,
            "unit": "ns/op",
            "extra": "259029 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - B/op",
            "value": 2162,
            "unit": "B/op",
            "extra": "259029 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - allocs/op",
            "value": 37,
            "unit": "allocs/op",
            "extra": "259029 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD",
            "value": 4343,
            "unit": "ns/op\t    2137 B/op\t      36 allocs/op",
            "extra": "276352 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - ns/op",
            "value": 4343,
            "unit": "ns/op",
            "extra": "276352 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - B/op",
            "value": 2137,
            "unit": "B/op",
            "extra": "276352 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - allocs/op",
            "value": 36,
            "unit": "allocs/op",
            "extra": "276352 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions",
            "value": 121425,
            "unit": "ns/op\t    7627 B/op\t     133 allocs/op",
            "extra": "9392 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - ns/op",
            "value": 121425,
            "unit": "ns/op",
            "extra": "9392 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - B/op",
            "value": 7627,
            "unit": "B/op",
            "extra": "9392 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - allocs/op",
            "value": 133,
            "unit": "allocs/op",
            "extra": "9392 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS",
            "value": 6073,
            "unit": "ns/op\t    3725 B/op\t      61 allocs/op",
            "extra": "185186 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - ns/op",
            "value": 6073,
            "unit": "ns/op",
            "extra": "185186 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - B/op",
            "value": 3725,
            "unit": "B/op",
            "extra": "185186 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - allocs/op",
            "value": 61,
            "unit": "allocs/op",
            "extra": "185186 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent",
            "value": 3071,
            "unit": "ns/op\t    2321 B/op\t      42 allocs/op",
            "extra": "395240 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - ns/op",
            "value": 3071,
            "unit": "ns/op",
            "extra": "395240 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - B/op",
            "value": 2321,
            "unit": "B/op",
            "extra": "395240 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - allocs/op",
            "value": 42,
            "unit": "allocs/op",
            "extra": "395240 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get",
            "value": 171.3,
            "unit": "ns/op\t      88 B/op\t       3 allocs/op",
            "extra": "7040959 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - ns/op",
            "value": 171.3,
            "unit": "ns/op",
            "extra": "7040959 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - B/op",
            "value": 88,
            "unit": "B/op",
            "extra": "7040959 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "7040959 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set",
            "value": 501.6,
            "unit": "ns/op\t     132 B/op\t       4 allocs/op",
            "extra": "2391182 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - ns/op",
            "value": 501.6,
            "unit": "ns/op",
            "extra": "2391182 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - B/op",
            "value": 132,
            "unit": "B/op",
            "extra": "2391182 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "2391182 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient",
            "value": 94314,
            "unit": "ns/op\t    3387 B/op\t      56 allocs/op",
            "extra": "12728 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - ns/op",
            "value": 94314,
            "unit": "ns/op",
            "extra": "12728 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - B/op",
            "value": 3387,
            "unit": "B/op",
            "extra": "12728 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - allocs/op",
            "value": 56,
            "unit": "allocs/op",
            "extra": "12728 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "rm_hull@yahoo.co.uk",
            "name": "Richard Hull",
            "username": "rm-hull"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "b6afac068315389b8f4133af2430a98593aee97f",
          "message": "feat(web): add 5-minute rolling average line to time series chart (#260)\n\n* feat(web): add 5-minute rolling average line to time series chart\n\nCompute a sliding 5-minute window average and render it as a dashed red\nline beneath the main count area to provide trend visibility.\n\n* refactor(web): extract TimeSeriesPoint type to avoid duplication",
          "timestamp": "2026-07-31T01:05:22+01:00",
          "tree_id": "b971285cc1257f19e1d4db3a757e02aabc75cff1",
          "url": "https://github.com/rm-hull/dot-block/commit/b6afac068315389b8f4133af2430a98593aee97f"
        },
        "date": 1785456483835,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDNSDispatcher/CacheHit",
            "value": 5012,
            "unit": "ns/op\t    2346 B/op\t      43 allocs/op",
            "extra": "227097 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - ns/op",
            "value": 5012,
            "unit": "ns/op",
            "extra": "227097 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - B/op",
            "value": 2346,
            "unit": "B/op",
            "extra": "227097 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - allocs/op",
            "value": 43,
            "unit": "allocs/op",
            "extra": "227097 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME",
            "value": 5109,
            "unit": "ns/op\t    2434 B/op\t      44 allocs/op",
            "extra": "224180 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - ns/op",
            "value": 5109,
            "unit": "ns/op",
            "extra": "224180 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - B/op",
            "value": 2434,
            "unit": "B/op",
            "extra": "224180 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "224180 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss",
            "value": 114260,
            "unit": "ns/op\t    6806 B/op\t     116 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - ns/op",
            "value": 114260,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - B/op",
            "value": 6806,
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
            "value": 4619,
            "unit": "ns/op\t    2378 B/op\t      45 allocs/op",
            "extra": "216928 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - ns/op",
            "value": 4619,
            "unit": "ns/op",
            "extra": "216928 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - B/op",
            "value": 2378,
            "unit": "B/op",
            "extra": "216928 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - allocs/op",
            "value": 45,
            "unit": "allocs/op",
            "extra": "216928 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE",
            "value": 4806,
            "unit": "ns/op\t    2490 B/op\t      49 allocs/op",
            "extra": "252128 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - ns/op",
            "value": 4806,
            "unit": "ns/op",
            "extra": "252128 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - B/op",
            "value": 2490,
            "unit": "B/op",
            "extra": "252128 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - allocs/op",
            "value": 49,
            "unit": "allocs/op",
            "extra": "252128 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD",
            "value": 4451,
            "unit": "ns/op\t    2162 B/op\t      37 allocs/op",
            "extra": "266862 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - ns/op",
            "value": 4451,
            "unit": "ns/op",
            "extra": "266862 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - B/op",
            "value": 2162,
            "unit": "B/op",
            "extra": "266862 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - allocs/op",
            "value": 37,
            "unit": "allocs/op",
            "extra": "266862 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD",
            "value": 4161,
            "unit": "ns/op\t    2138 B/op\t      36 allocs/op",
            "extra": "277443 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - ns/op",
            "value": 4161,
            "unit": "ns/op",
            "extra": "277443 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - B/op",
            "value": 2138,
            "unit": "B/op",
            "extra": "277443 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - allocs/op",
            "value": 36,
            "unit": "allocs/op",
            "extra": "277443 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions",
            "value": 111783,
            "unit": "ns/op\t    7621 B/op\t     134 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - ns/op",
            "value": 111783,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - B/op",
            "value": 7621,
            "unit": "B/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - allocs/op",
            "value": 134,
            "unit": "allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS",
            "value": 5807,
            "unit": "ns/op\t    3658 B/op\t      61 allocs/op",
            "extra": "205596 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - ns/op",
            "value": 5807,
            "unit": "ns/op",
            "extra": "205596 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - B/op",
            "value": 3658,
            "unit": "B/op",
            "extra": "205596 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - allocs/op",
            "value": 61,
            "unit": "allocs/op",
            "extra": "205596 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent",
            "value": 2546,
            "unit": "ns/op\t    2321 B/op\t      42 allocs/op",
            "extra": "415581 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - ns/op",
            "value": 2546,
            "unit": "ns/op",
            "extra": "415581 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - B/op",
            "value": 2321,
            "unit": "B/op",
            "extra": "415581 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - allocs/op",
            "value": 42,
            "unit": "allocs/op",
            "extra": "415581 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get",
            "value": 166.5,
            "unit": "ns/op\t      88 B/op\t       3 allocs/op",
            "extra": "7151305 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - ns/op",
            "value": 166.5,
            "unit": "ns/op",
            "extra": "7151305 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - B/op",
            "value": 88,
            "unit": "B/op",
            "extra": "7151305 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "7151305 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set",
            "value": 458.7,
            "unit": "ns/op\t     131 B/op\t       4 allocs/op",
            "extra": "2612010 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - ns/op",
            "value": 458.7,
            "unit": "ns/op",
            "extra": "2612010 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - B/op",
            "value": 131,
            "unit": "B/op",
            "extra": "2612010 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "2612010 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient",
            "value": 78913,
            "unit": "ns/op\t    3386 B/op\t      56 allocs/op",
            "extra": "15261 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - ns/op",
            "value": 78913,
            "unit": "ns/op",
            "extra": "15261 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - B/op",
            "value": 3386,
            "unit": "B/op",
            "extra": "15261 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - allocs/op",
            "value": 56,
            "unit": "allocs/op",
            "extra": "15261 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "rm_hull@yahoo.co.uk",
            "name": "Richard Hull",
            "username": "rm-hull"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "848eb3d21e518d830fee2f061e74d99949830587",
          "message": "fix(web): keep time-series chart scrolling when no new data arrives (#261)\n\nThe chart's axis domain was anchored to the timestamp of the most\nrecent data point, so when the event stream went quiet the window\nfroze in place. Track wall-clock time and anchor the window end to\nnow (falling back to the latest data point), which lets old data\nscroll off the left edge and keeps the time axis live.",
          "timestamp": "2026-07-31T01:27:07+01:00",
          "tree_id": "385353fc9f4303ba9eb3e8222994c63a1ab95b3a",
          "url": "https://github.com/rm-hull/dot-block/commit/848eb3d21e518d830fee2f061e74d99949830587"
        },
        "date": 1785457825660,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDNSDispatcher/CacheHit",
            "value": 5089,
            "unit": "ns/op\t    2346 B/op\t      43 allocs/op",
            "extra": "228909 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - ns/op",
            "value": 5089,
            "unit": "ns/op",
            "extra": "228909 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - B/op",
            "value": 2346,
            "unit": "B/op",
            "extra": "228909 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - allocs/op",
            "value": 43,
            "unit": "allocs/op",
            "extra": "228909 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME",
            "value": 5293,
            "unit": "ns/op\t    2434 B/op\t      44 allocs/op",
            "extra": "219810 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - ns/op",
            "value": 5293,
            "unit": "ns/op",
            "extra": "219810 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - B/op",
            "value": 2434,
            "unit": "B/op",
            "extra": "219810 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "219810 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss",
            "value": 120001,
            "unit": "ns/op\t    6805 B/op\t     116 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - ns/op",
            "value": 120001,
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
            "value": 4825,
            "unit": "ns/op\t    2378 B/op\t      45 allocs/op",
            "extra": "260522 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - ns/op",
            "value": 4825,
            "unit": "ns/op",
            "extra": "260522 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - B/op",
            "value": 2378,
            "unit": "B/op",
            "extra": "260522 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - allocs/op",
            "value": 45,
            "unit": "allocs/op",
            "extra": "260522 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE",
            "value": 4952,
            "unit": "ns/op\t    2490 B/op\t      49 allocs/op",
            "extra": "235786 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - ns/op",
            "value": 4952,
            "unit": "ns/op",
            "extra": "235786 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - B/op",
            "value": 2490,
            "unit": "B/op",
            "extra": "235786 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - allocs/op",
            "value": 49,
            "unit": "allocs/op",
            "extra": "235786 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD",
            "value": 5064,
            "unit": "ns/op\t    2161 B/op\t      37 allocs/op",
            "extra": "221391 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - ns/op",
            "value": 5064,
            "unit": "ns/op",
            "extra": "221391 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - B/op",
            "value": 2161,
            "unit": "B/op",
            "extra": "221391 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - allocs/op",
            "value": 37,
            "unit": "allocs/op",
            "extra": "221391 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD",
            "value": 4299,
            "unit": "ns/op\t    2137 B/op\t      36 allocs/op",
            "extra": "281684 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - ns/op",
            "value": 4299,
            "unit": "ns/op",
            "extra": "281684 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - B/op",
            "value": 2137,
            "unit": "B/op",
            "extra": "281684 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - allocs/op",
            "value": 36,
            "unit": "allocs/op",
            "extra": "281684 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions",
            "value": 122440,
            "unit": "ns/op\t    7622 B/op\t     134 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - ns/op",
            "value": 122440,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - B/op",
            "value": 7622,
            "unit": "B/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - allocs/op",
            "value": 134,
            "unit": "allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS",
            "value": 5928,
            "unit": "ns/op\t    3725 B/op\t      61 allocs/op",
            "extra": "184645 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - ns/op",
            "value": 5928,
            "unit": "ns/op",
            "extra": "184645 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - B/op",
            "value": 3725,
            "unit": "B/op",
            "extra": "184645 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - allocs/op",
            "value": 61,
            "unit": "allocs/op",
            "extra": "184645 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent",
            "value": 2915,
            "unit": "ns/op\t    2321 B/op\t      42 allocs/op",
            "extra": "371474 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - ns/op",
            "value": 2915,
            "unit": "ns/op",
            "extra": "371474 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - B/op",
            "value": 2321,
            "unit": "B/op",
            "extra": "371474 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - allocs/op",
            "value": 42,
            "unit": "allocs/op",
            "extra": "371474 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get",
            "value": 167.1,
            "unit": "ns/op\t      88 B/op\t       3 allocs/op",
            "extra": "7125250 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - ns/op",
            "value": 167.1,
            "unit": "ns/op",
            "extra": "7125250 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - B/op",
            "value": 88,
            "unit": "B/op",
            "extra": "7125250 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "7125250 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set",
            "value": 488,
            "unit": "ns/op\t     128 B/op\t       4 allocs/op",
            "extra": "2477662 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - ns/op",
            "value": 488,
            "unit": "ns/op",
            "extra": "2477662 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - B/op",
            "value": 128,
            "unit": "B/op",
            "extra": "2477662 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "2477662 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient",
            "value": 98837,
            "unit": "ns/op\t    3386 B/op\t      56 allocs/op",
            "extra": "12104 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - ns/op",
            "value": 98837,
            "unit": "ns/op",
            "extra": "12104 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - B/op",
            "value": 3386,
            "unit": "B/op",
            "extra": "12104 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - allocs/op",
            "value": 56,
            "unit": "allocs/op",
            "extra": "12104 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "9ee9bf0e57ba44f39257fdd5005a480673234f83",
          "message": "chore(deps): Bump docker/login-action from 4 to 4.5.2 (#262)\n\nBumps [docker/login-action](https://github.com/docker/login-action) from 4 to 4.5.2.\n- [Release notes](https://github.com/docker/login-action/releases)\n- [Commits](https://github.com/docker/login-action/compare/v4...v4.5.2)\n\n---\nupdated-dependencies:\n- dependency-name: docker/login-action\n  dependency-version: 4.5.2\n  dependency-type: direct:production\n  update-type: version-update:semver-minor\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
          "timestamp": "2026-07-31T08:02:29+01:00",
          "tree_id": "24c9a9ac53a2718bfac2e9f1afd99eb186b17577",
          "url": "https://github.com/rm-hull/dot-block/commit/9ee9bf0e57ba44f39257fdd5005a480673234f83"
        },
        "date": 1785481524301,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDNSDispatcher/CacheHit",
            "value": 4985,
            "unit": "ns/op\t    2346 B/op\t      43 allocs/op",
            "extra": "216718 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - ns/op",
            "value": 4985,
            "unit": "ns/op",
            "extra": "216718 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - B/op",
            "value": 2346,
            "unit": "B/op",
            "extra": "216718 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - allocs/op",
            "value": 43,
            "unit": "allocs/op",
            "extra": "216718 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME",
            "value": 5141,
            "unit": "ns/op\t    2434 B/op\t      44 allocs/op",
            "extra": "226486 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - ns/op",
            "value": 5141,
            "unit": "ns/op",
            "extra": "226486 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - B/op",
            "value": 2434,
            "unit": "B/op",
            "extra": "226486 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "226486 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss",
            "value": 111407,
            "unit": "ns/op\t    6807 B/op\t     116 allocs/op",
            "extra": "9949 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - ns/op",
            "value": 111407,
            "unit": "ns/op",
            "extra": "9949 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - B/op",
            "value": 6807,
            "unit": "B/op",
            "extra": "9949 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - allocs/op",
            "value": 116,
            "unit": "allocs/op",
            "extra": "9949 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked",
            "value": 4649,
            "unit": "ns/op\t    2378 B/op\t      45 allocs/op",
            "extra": "261987 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - ns/op",
            "value": 4649,
            "unit": "ns/op",
            "extra": "261987 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - B/op",
            "value": 2378,
            "unit": "B/op",
            "extra": "261987 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - allocs/op",
            "value": 45,
            "unit": "allocs/op",
            "extra": "261987 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE",
            "value": 4847,
            "unit": "ns/op\t    2490 B/op\t      49 allocs/op",
            "extra": "244262 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - ns/op",
            "value": 4847,
            "unit": "ns/op",
            "extra": "244262 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - B/op",
            "value": 2490,
            "unit": "B/op",
            "extra": "244262 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - allocs/op",
            "value": 49,
            "unit": "allocs/op",
            "extra": "244262 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD",
            "value": 4545,
            "unit": "ns/op\t    2161 B/op\t      37 allocs/op",
            "extra": "231829 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - ns/op",
            "value": 4545,
            "unit": "ns/op",
            "extra": "231829 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - B/op",
            "value": 2161,
            "unit": "B/op",
            "extra": "231829 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - allocs/op",
            "value": 37,
            "unit": "allocs/op",
            "extra": "231829 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD",
            "value": 4702,
            "unit": "ns/op\t    2138 B/op\t      36 allocs/op",
            "extra": "279319 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - ns/op",
            "value": 4702,
            "unit": "ns/op",
            "extra": "279319 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - B/op",
            "value": 2138,
            "unit": "B/op",
            "extra": "279319 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - allocs/op",
            "value": 36,
            "unit": "allocs/op",
            "extra": "279319 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions",
            "value": 116358,
            "unit": "ns/op\t    7622 B/op\t     134 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - ns/op",
            "value": 116358,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - B/op",
            "value": 7622,
            "unit": "B/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - allocs/op",
            "value": 134,
            "unit": "allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS",
            "value": 6244,
            "unit": "ns/op\t    3692 B/op\t      60 allocs/op",
            "extra": "171591 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - ns/op",
            "value": 6244,
            "unit": "ns/op",
            "extra": "171591 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - B/op",
            "value": 3692,
            "unit": "B/op",
            "extra": "171591 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "171591 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent",
            "value": 2793,
            "unit": "ns/op\t    2321 B/op\t      42 allocs/op",
            "extra": "374367 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - ns/op",
            "value": 2793,
            "unit": "ns/op",
            "extra": "374367 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - B/op",
            "value": 2321,
            "unit": "B/op",
            "extra": "374367 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - allocs/op",
            "value": 42,
            "unit": "allocs/op",
            "extra": "374367 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get",
            "value": 171.5,
            "unit": "ns/op\t      88 B/op\t       3 allocs/op",
            "extra": "6894975 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - ns/op",
            "value": 171.5,
            "unit": "ns/op",
            "extra": "6894975 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - B/op",
            "value": 88,
            "unit": "B/op",
            "extra": "6894975 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "6894975 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set",
            "value": 454.7,
            "unit": "ns/op\t     126 B/op\t       4 allocs/op",
            "extra": "2685376 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - ns/op",
            "value": 454.7,
            "unit": "ns/op",
            "extra": "2685376 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - B/op",
            "value": 126,
            "unit": "B/op",
            "extra": "2685376 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "2685376 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient",
            "value": 80209,
            "unit": "ns/op\t    3387 B/op\t      56 allocs/op",
            "extra": "14828 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - ns/op",
            "value": 80209,
            "unit": "ns/op",
            "extra": "14828 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - B/op",
            "value": 3387,
            "unit": "B/op",
            "extra": "14828 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - allocs/op",
            "value": 56,
            "unit": "allocs/op",
            "extra": "14828 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "rm_hull@yahoo.co.uk",
            "name": "Richard Hull",
            "username": "rm-hull"
          },
          "committer": {
            "email": "rm_hull@yahoo.co.uk",
            "name": "Richard Hull",
            "username": "rm-hull"
          },
          "distinct": true,
          "id": "8db797d518f6c928222e7e7c028784e6415e07f1",
          "message": "Support subdomain hierarchy checking in blocklist\n\n- Update BlockList.IsBlocked to iteratively check parent subdomains up to the registrable apex domain (EffectiveTLDPlusOne).\n- This ensures subdomains (e.g. 8.lox.legalendowmad.com) are correctly blocked when an ancestor domain (e.g. lox.legalendowmad.com) is present on the blocklist.\n- Add TestBlocklist_SubdomainHierarchy unit tests covering various subdomain depths.",
          "timestamp": "2026-07-31T09:03:32+01:00",
          "tree_id": "094aa3be5a2da9ffcd77cb93312f31c357b27b1c",
          "url": "https://github.com/rm-hull/dot-block/commit/8db797d518f6c928222e7e7c028784e6415e07f1"
        },
        "date": 1785485201431,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDNSDispatcher/CacheHit",
            "value": 5114,
            "unit": "ns/op\t    2346 B/op\t      43 allocs/op",
            "extra": "232489 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - ns/op",
            "value": 5114,
            "unit": "ns/op",
            "extra": "232489 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - B/op",
            "value": 2346,
            "unit": "B/op",
            "extra": "232489 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - allocs/op",
            "value": 43,
            "unit": "allocs/op",
            "extra": "232489 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME",
            "value": 5349,
            "unit": "ns/op\t    2434 B/op\t      44 allocs/op",
            "extra": "221281 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - ns/op",
            "value": 5349,
            "unit": "ns/op",
            "extra": "221281 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - B/op",
            "value": 2434,
            "unit": "B/op",
            "extra": "221281 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "221281 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss",
            "value": 120605,
            "unit": "ns/op\t    6806 B/op\t     116 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - ns/op",
            "value": 120605,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - B/op",
            "value": 6806,
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
            "value": 4759,
            "unit": "ns/op\t    2378 B/op\t      45 allocs/op",
            "extra": "261486 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - ns/op",
            "value": 4759,
            "unit": "ns/op",
            "extra": "261486 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - B/op",
            "value": 2378,
            "unit": "B/op",
            "extra": "261486 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - allocs/op",
            "value": 45,
            "unit": "allocs/op",
            "extra": "261486 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE",
            "value": 4902,
            "unit": "ns/op\t    2490 B/op\t      49 allocs/op",
            "extra": "227682 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - ns/op",
            "value": 4902,
            "unit": "ns/op",
            "extra": "227682 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - B/op",
            "value": 2490,
            "unit": "B/op",
            "extra": "227682 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - allocs/op",
            "value": 49,
            "unit": "allocs/op",
            "extra": "227682 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD",
            "value": 5093,
            "unit": "ns/op\t    2161 B/op\t      37 allocs/op",
            "extra": "243693 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - ns/op",
            "value": 5093,
            "unit": "ns/op",
            "extra": "243693 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - B/op",
            "value": 2161,
            "unit": "B/op",
            "extra": "243693 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - allocs/op",
            "value": 37,
            "unit": "allocs/op",
            "extra": "243693 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD",
            "value": 4714,
            "unit": "ns/op\t    2137 B/op\t      36 allocs/op",
            "extra": "228536 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - ns/op",
            "value": 4714,
            "unit": "ns/op",
            "extra": "228536 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - B/op",
            "value": 2137,
            "unit": "B/op",
            "extra": "228536 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - allocs/op",
            "value": 36,
            "unit": "allocs/op",
            "extra": "228536 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions",
            "value": 121281,
            "unit": "ns/op\t    7624 B/op\t     134 allocs/op",
            "extra": "9632 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - ns/op",
            "value": 121281,
            "unit": "ns/op",
            "extra": "9632 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - B/op",
            "value": 7624,
            "unit": "B/op",
            "extra": "9632 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - allocs/op",
            "value": 134,
            "unit": "allocs/op",
            "extra": "9632 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS",
            "value": 5924,
            "unit": "ns/op\t    3700 B/op\t      61 allocs/op",
            "extra": "187470 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - ns/op",
            "value": 5924,
            "unit": "ns/op",
            "extra": "187470 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - B/op",
            "value": 3700,
            "unit": "B/op",
            "extra": "187470 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - allocs/op",
            "value": 61,
            "unit": "allocs/op",
            "extra": "187470 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent",
            "value": 2930,
            "unit": "ns/op\t    2321 B/op\t      42 allocs/op",
            "extra": "357022 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - ns/op",
            "value": 2930,
            "unit": "ns/op",
            "extra": "357022 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - B/op",
            "value": 2321,
            "unit": "B/op",
            "extra": "357022 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - allocs/op",
            "value": 42,
            "unit": "allocs/op",
            "extra": "357022 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get",
            "value": 167.6,
            "unit": "ns/op\t      88 B/op\t       3 allocs/op",
            "extra": "7045537 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - ns/op",
            "value": 167.6,
            "unit": "ns/op",
            "extra": "7045537 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - B/op",
            "value": 88,
            "unit": "B/op",
            "extra": "7045537 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "7045537 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set",
            "value": 475.9,
            "unit": "ns/op\t     127 B/op\t       4 allocs/op",
            "extra": "2552305 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - ns/op",
            "value": 475.9,
            "unit": "ns/op",
            "extra": "2552305 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - B/op",
            "value": 127,
            "unit": "B/op",
            "extra": "2552305 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "2552305 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient",
            "value": 98358,
            "unit": "ns/op\t    3386 B/op\t      56 allocs/op",
            "extra": "12291 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - ns/op",
            "value": 98358,
            "unit": "ns/op",
            "extra": "12291 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - B/op",
            "value": 3386,
            "unit": "B/op",
            "extra": "12291 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - allocs/op",
            "value": 56,
            "unit": "allocs/op",
            "extra": "12291 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "rm_hull@yahoo.co.uk",
            "name": "Richard Hull",
            "username": "rm-hull"
          },
          "committer": {
            "email": "rm_hull@yahoo.co.uk",
            "name": "Richard Hull",
            "username": "rm-hull"
          },
          "distinct": true,
          "id": "d1ab48e35aaa5b50263406196c93f3f341120387",
          "message": "fix: support subdomain hierarchy checking in blocklist\n\n- Update BlockList.IsBlocked to iteratively check parent subdomains up to the registrable apex domain (EffectiveTLDPlusOne).\n- This ensures subdomains (e.g. 8.lox.legalendowmad.com) are correctly blocked when an ancestor domain (e.g. lox.legalendowmad.com) is present on the blocklist.\n- Add TestBlocklist_SubdomainHierarchy unit tests covering various subdomain depths.",
          "timestamp": "2026-07-31T09:09:13+01:00",
          "tree_id": "094aa3be5a2da9ffcd77cb93312f31c357b27b1c",
          "url": "https://github.com/rm-hull/dot-block/commit/d1ab48e35aaa5b50263406196c93f3f341120387"
        },
        "date": 1785485538649,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDNSDispatcher/CacheHit",
            "value": 5205,
            "unit": "ns/op\t    2346 B/op\t      43 allocs/op",
            "extra": "223526 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - ns/op",
            "value": 5205,
            "unit": "ns/op",
            "extra": "223526 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - B/op",
            "value": 2346,
            "unit": "B/op",
            "extra": "223526 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - allocs/op",
            "value": 43,
            "unit": "allocs/op",
            "extra": "223526 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME",
            "value": 5217,
            "unit": "ns/op\t    2434 B/op\t      43 allocs/op",
            "extra": "222260 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - ns/op",
            "value": 5217,
            "unit": "ns/op",
            "extra": "222260 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - B/op",
            "value": 2434,
            "unit": "B/op",
            "extra": "222260 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - allocs/op",
            "value": 43,
            "unit": "allocs/op",
            "extra": "222260 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss",
            "value": 120553,
            "unit": "ns/op\t    6805 B/op\t     116 allocs/op",
            "extra": "9943 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - ns/op",
            "value": 120553,
            "unit": "ns/op",
            "extra": "9943 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - B/op",
            "value": 6805,
            "unit": "B/op",
            "extra": "9943 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - allocs/op",
            "value": 116,
            "unit": "allocs/op",
            "extra": "9943 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked",
            "value": 4847,
            "unit": "ns/op\t    2378 B/op\t      45 allocs/op",
            "extra": "245052 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - ns/op",
            "value": 4847,
            "unit": "ns/op",
            "extra": "245052 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - B/op",
            "value": 2378,
            "unit": "B/op",
            "extra": "245052 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - allocs/op",
            "value": 45,
            "unit": "allocs/op",
            "extra": "245052 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE",
            "value": 4951,
            "unit": "ns/op\t    2490 B/op\t      49 allocs/op",
            "extra": "242169 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - ns/op",
            "value": 4951,
            "unit": "ns/op",
            "extra": "242169 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - B/op",
            "value": 2490,
            "unit": "B/op",
            "extra": "242169 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - allocs/op",
            "value": 49,
            "unit": "allocs/op",
            "extra": "242169 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD",
            "value": 5008,
            "unit": "ns/op\t    2161 B/op\t      37 allocs/op",
            "extra": "235993 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - ns/op",
            "value": 5008,
            "unit": "ns/op",
            "extra": "235993 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - B/op",
            "value": 2161,
            "unit": "B/op",
            "extra": "235993 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - allocs/op",
            "value": 37,
            "unit": "allocs/op",
            "extra": "235993 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD",
            "value": 4533,
            "unit": "ns/op\t    2137 B/op\t      36 allocs/op",
            "extra": "251779 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - ns/op",
            "value": 4533,
            "unit": "ns/op",
            "extra": "251779 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - B/op",
            "value": 2137,
            "unit": "B/op",
            "extra": "251779 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - allocs/op",
            "value": 36,
            "unit": "allocs/op",
            "extra": "251779 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions",
            "value": 125250,
            "unit": "ns/op\t    7625 B/op\t     134 allocs/op",
            "extra": "9528 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - ns/op",
            "value": 125250,
            "unit": "ns/op",
            "extra": "9528 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - B/op",
            "value": 7625,
            "unit": "B/op",
            "extra": "9528 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - allocs/op",
            "value": 134,
            "unit": "allocs/op",
            "extra": "9528 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS",
            "value": 6000,
            "unit": "ns/op\t    3700 B/op\t      61 allocs/op",
            "extra": "183238 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - ns/op",
            "value": 6000,
            "unit": "ns/op",
            "extra": "183238 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - B/op",
            "value": 3700,
            "unit": "B/op",
            "extra": "183238 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - allocs/op",
            "value": 61,
            "unit": "allocs/op",
            "extra": "183238 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent",
            "value": 2917,
            "unit": "ns/op\t    2321 B/op\t      42 allocs/op",
            "extra": "365703 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - ns/op",
            "value": 2917,
            "unit": "ns/op",
            "extra": "365703 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - B/op",
            "value": 2321,
            "unit": "B/op",
            "extra": "365703 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - allocs/op",
            "value": 42,
            "unit": "allocs/op",
            "extra": "365703 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get",
            "value": 166.2,
            "unit": "ns/op\t      88 B/op\t       3 allocs/op",
            "extra": "7147796 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - ns/op",
            "value": 166.2,
            "unit": "ns/op",
            "extra": "7147796 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - B/op",
            "value": 88,
            "unit": "B/op",
            "extra": "7147796 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "7147796 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set",
            "value": 457.3,
            "unit": "ns/op\t     122 B/op\t       4 allocs/op",
            "extra": "2667524 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - ns/op",
            "value": 457.3,
            "unit": "ns/op",
            "extra": "2667524 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - B/op",
            "value": 122,
            "unit": "B/op",
            "extra": "2667524 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "2667524 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient",
            "value": 95463,
            "unit": "ns/op\t    3387 B/op\t      56 allocs/op",
            "extra": "12585 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - ns/op",
            "value": 95463,
            "unit": "ns/op",
            "extra": "12585 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - B/op",
            "value": 3387,
            "unit": "B/op",
            "extra": "12585 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - allocs/op",
            "value": 56,
            "unit": "allocs/op",
            "extra": "12585 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "rm_hull@yahoo.co.uk",
            "name": "Richard Hull",
            "username": "rm-hull"
          },
          "committer": {
            "email": "rm_hull@yahoo.co.uk",
            "name": "Richard Hull",
            "username": "rm-hull"
          },
          "distinct": true,
          "id": "6c591dc1fea6173eeab9a2168d331392cdb30293",
          "message": "fix: update hagezi blocklist URL to correct path (hosts/pro.txt -> adblock/pro.txt)",
          "timestamp": "2026-07-31T10:29:29+01:00",
          "tree_id": "007a3f9ff22b4bd3a4b7c28bd98dd8b2900ecbce",
          "url": "https://github.com/rm-hull/dot-block/commit/6c591dc1fea6173eeab9a2168d331392cdb30293"
        },
        "date": 1785490338245,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDNSDispatcher/CacheHit",
            "value": 5190,
            "unit": "ns/op\t    2346 B/op\t      43 allocs/op",
            "extra": "223676 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - ns/op",
            "value": 5190,
            "unit": "ns/op",
            "extra": "223676 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - B/op",
            "value": 2346,
            "unit": "B/op",
            "extra": "223676 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - allocs/op",
            "value": 43,
            "unit": "allocs/op",
            "extra": "223676 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME",
            "value": 5440,
            "unit": "ns/op\t    2434 B/op\t      44 allocs/op",
            "extra": "224434 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - ns/op",
            "value": 5440,
            "unit": "ns/op",
            "extra": "224434 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - B/op",
            "value": 2434,
            "unit": "B/op",
            "extra": "224434 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "224434 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss",
            "value": 112337,
            "unit": "ns/op\t    6806 B/op\t     116 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - ns/op",
            "value": 112337,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - B/op",
            "value": 6806,
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
            "value": 4633,
            "unit": "ns/op\t    2378 B/op\t      45 allocs/op",
            "extra": "252806 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - ns/op",
            "value": 4633,
            "unit": "ns/op",
            "extra": "252806 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - B/op",
            "value": 2378,
            "unit": "B/op",
            "extra": "252806 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - allocs/op",
            "value": 45,
            "unit": "allocs/op",
            "extra": "252806 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE",
            "value": 4982,
            "unit": "ns/op\t    2490 B/op\t      49 allocs/op",
            "extra": "245976 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - ns/op",
            "value": 4982,
            "unit": "ns/op",
            "extra": "245976 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - B/op",
            "value": 2490,
            "unit": "B/op",
            "extra": "245976 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - allocs/op",
            "value": 49,
            "unit": "allocs/op",
            "extra": "245976 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD",
            "value": 4908,
            "unit": "ns/op\t    2162 B/op\t      37 allocs/op",
            "extra": "235725 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - ns/op",
            "value": 4908,
            "unit": "ns/op",
            "extra": "235725 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - B/op",
            "value": 2162,
            "unit": "B/op",
            "extra": "235725 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - allocs/op",
            "value": 37,
            "unit": "allocs/op",
            "extra": "235725 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD",
            "value": 4312,
            "unit": "ns/op\t    2138 B/op\t      36 allocs/op",
            "extra": "265978 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - ns/op",
            "value": 4312,
            "unit": "ns/op",
            "extra": "265978 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - B/op",
            "value": 2138,
            "unit": "B/op",
            "extra": "265978 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - allocs/op",
            "value": 36,
            "unit": "allocs/op",
            "extra": "265978 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions",
            "value": 114682,
            "unit": "ns/op\t    7621 B/op\t     134 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - ns/op",
            "value": 114682,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - B/op",
            "value": 7621,
            "unit": "B/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - allocs/op",
            "value": 134,
            "unit": "allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS",
            "value": 6606,
            "unit": "ns/op\t    3709 B/op\t      61 allocs/op",
            "extra": "184994 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - ns/op",
            "value": 6606,
            "unit": "ns/op",
            "extra": "184994 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - B/op",
            "value": 3709,
            "unit": "B/op",
            "extra": "184994 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - allocs/op",
            "value": 61,
            "unit": "allocs/op",
            "extra": "184994 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent",
            "value": 2624,
            "unit": "ns/op\t    2321 B/op\t      42 allocs/op",
            "extra": "411559 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - ns/op",
            "value": 2624,
            "unit": "ns/op",
            "extra": "411559 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - B/op",
            "value": 2321,
            "unit": "B/op",
            "extra": "411559 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - allocs/op",
            "value": 42,
            "unit": "allocs/op",
            "extra": "411559 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get",
            "value": 165.6,
            "unit": "ns/op\t      88 B/op\t       3 allocs/op",
            "extra": "7095337 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - ns/op",
            "value": 165.6,
            "unit": "ns/op",
            "extra": "7095337 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - B/op",
            "value": 88,
            "unit": "B/op",
            "extra": "7095337 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "7095337 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set",
            "value": 456.7,
            "unit": "ns/op\t     117 B/op\t       4 allocs/op",
            "extra": "2669530 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - ns/op",
            "value": 456.7,
            "unit": "ns/op",
            "extra": "2669530 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - B/op",
            "value": 117,
            "unit": "B/op",
            "extra": "2669530 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "2669530 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient",
            "value": 80280,
            "unit": "ns/op\t    3386 B/op\t      56 allocs/op",
            "extra": "14925 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - ns/op",
            "value": 80280,
            "unit": "ns/op",
            "extra": "14925 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - B/op",
            "value": 3386,
            "unit": "B/op",
            "extra": "14925 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - allocs/op",
            "value": 56,
            "unit": "allocs/op",
            "extra": "14925 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "rm_hull@yahoo.co.uk",
            "name": "Richard Hull",
            "username": "rm-hull"
          },
          "committer": {
            "email": "rm_hull@yahoo.co.uk",
            "name": "Richard Hull",
            "username": "rm-hull"
          },
          "distinct": true,
          "id": "d1ab48e35aaa5b50263406196c93f3f341120387",
          "message": "fix: support subdomain hierarchy checking in blocklist\n\n- Update BlockList.IsBlocked to iteratively check parent subdomains up to the registrable apex domain (EffectiveTLDPlusOne).\n- This ensures subdomains (e.g. 8.lox.legalendowmad.com) are correctly blocked when an ancestor domain (e.g. lox.legalendowmad.com) is present on the blocklist.\n- Add TestBlocklist_SubdomainHierarchy unit tests covering various subdomain depths.",
          "timestamp": "2026-07-31T09:09:13+01:00",
          "tree_id": "094aa3be5a2da9ffcd77cb93312f31c357b27b1c",
          "url": "https://github.com/rm-hull/dot-block/commit/d1ab48e35aaa5b50263406196c93f3f341120387"
        },
        "date": 1785491667925,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDNSDispatcher/CacheHit",
            "value": 4963,
            "unit": "ns/op\t    2346 B/op\t      43 allocs/op",
            "extra": "239056 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - ns/op",
            "value": 4963,
            "unit": "ns/op",
            "extra": "239056 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - B/op",
            "value": 2346,
            "unit": "B/op",
            "extra": "239056 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - allocs/op",
            "value": 43,
            "unit": "allocs/op",
            "extra": "239056 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME",
            "value": 5192,
            "unit": "ns/op\t    2434 B/op\t      44 allocs/op",
            "extra": "230589 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - ns/op",
            "value": 5192,
            "unit": "ns/op",
            "extra": "230589 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - B/op",
            "value": 2434,
            "unit": "B/op",
            "extra": "230589 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "230589 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss",
            "value": 113734,
            "unit": "ns/op\t    6805 B/op\t     116 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - ns/op",
            "value": 113734,
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
            "value": 4699,
            "unit": "ns/op\t    2378 B/op\t      45 allocs/op",
            "extra": "262132 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - ns/op",
            "value": 4699,
            "unit": "ns/op",
            "extra": "262132 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - B/op",
            "value": 2378,
            "unit": "B/op",
            "extra": "262132 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - allocs/op",
            "value": 45,
            "unit": "allocs/op",
            "extra": "262132 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE",
            "value": 4971,
            "unit": "ns/op\t    2490 B/op\t      49 allocs/op",
            "extra": "243696 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - ns/op",
            "value": 4971,
            "unit": "ns/op",
            "extra": "243696 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - B/op",
            "value": 2490,
            "unit": "B/op",
            "extra": "243696 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - allocs/op",
            "value": 49,
            "unit": "allocs/op",
            "extra": "243696 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD",
            "value": 5264,
            "unit": "ns/op\t    2161 B/op\t      37 allocs/op",
            "extra": "230205 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - ns/op",
            "value": 5264,
            "unit": "ns/op",
            "extra": "230205 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - B/op",
            "value": 2161,
            "unit": "B/op",
            "extra": "230205 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - allocs/op",
            "value": 37,
            "unit": "allocs/op",
            "extra": "230205 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD",
            "value": 4372,
            "unit": "ns/op\t    2137 B/op\t      36 allocs/op",
            "extra": "275397 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - ns/op",
            "value": 4372,
            "unit": "ns/op",
            "extra": "275397 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - B/op",
            "value": 2137,
            "unit": "B/op",
            "extra": "275397 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - allocs/op",
            "value": 36,
            "unit": "allocs/op",
            "extra": "275397 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions",
            "value": 116624,
            "unit": "ns/op\t    7621 B/op\t     134 allocs/op",
            "extra": "9984 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - ns/op",
            "value": 116624,
            "unit": "ns/op",
            "extra": "9984 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - B/op",
            "value": 7621,
            "unit": "B/op",
            "extra": "9984 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - allocs/op",
            "value": 134,
            "unit": "allocs/op",
            "extra": "9984 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS",
            "value": 5813,
            "unit": "ns/op\t    3692 B/op\t      61 allocs/op",
            "extra": "189885 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - ns/op",
            "value": 5813,
            "unit": "ns/op",
            "extra": "189885 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - B/op",
            "value": 3692,
            "unit": "B/op",
            "extra": "189885 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - allocs/op",
            "value": 61,
            "unit": "allocs/op",
            "extra": "189885 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent",
            "value": 2921,
            "unit": "ns/op\t    2321 B/op\t      42 allocs/op",
            "extra": "417393 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - ns/op",
            "value": 2921,
            "unit": "ns/op",
            "extra": "417393 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - B/op",
            "value": 2321,
            "unit": "B/op",
            "extra": "417393 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - allocs/op",
            "value": 42,
            "unit": "allocs/op",
            "extra": "417393 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get",
            "value": 170.6,
            "unit": "ns/op\t      88 B/op\t       3 allocs/op",
            "extra": "7004760 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - ns/op",
            "value": 170.6,
            "unit": "ns/op",
            "extra": "7004760 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - B/op",
            "value": 88,
            "unit": "B/op",
            "extra": "7004760 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "7004760 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set",
            "value": 458.6,
            "unit": "ns/op\t     117 B/op\t       4 allocs/op",
            "extra": "2625607 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - ns/op",
            "value": 458.6,
            "unit": "ns/op",
            "extra": "2625607 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - B/op",
            "value": 117,
            "unit": "B/op",
            "extra": "2625607 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "2625607 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient",
            "value": 92381,
            "unit": "ns/op\t    3386 B/op\t      56 allocs/op",
            "extra": "13152 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - ns/op",
            "value": 92381,
            "unit": "ns/op",
            "extra": "13152 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - B/op",
            "value": 3386,
            "unit": "B/op",
            "extra": "13152 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - allocs/op",
            "value": 56,
            "unit": "allocs/op",
            "extra": "13152 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "rm_hull@yahoo.co.uk",
            "name": "Richard Hull",
            "username": "rm-hull"
          },
          "committer": {
            "email": "rm_hull@yahoo.co.uk",
            "name": "Richard Hull",
            "username": "rm-hull"
          },
          "distinct": true,
          "id": "eec133c140d6d0f40a0761a222f4f7bff76d8339",
          "message": "fix(config): update default blocklist to hagezi pro.plus\n\nSwitch the default Hagezi blocklist source from `pro` (hosts format) to\n`pro.plus-onlydomains` via jsDelivr CDN for better coverage and\nimproved download performance.\n\nOld blocklist was 404ing",
          "timestamp": "2026-07-31T11:31:41+01:00",
          "tree_id": "8871e0a939e124a7634e6dccf80eed082104c5fa",
          "url": "https://github.com/rm-hull/dot-block/commit/eec133c140d6d0f40a0761a222f4f7bff76d8339"
        },
        "date": 1785494090908,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDNSDispatcher/CacheHit",
            "value": 5053,
            "unit": "ns/op\t    2346 B/op\t      43 allocs/op",
            "extra": "228645 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - ns/op",
            "value": 5053,
            "unit": "ns/op",
            "extra": "228645 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - B/op",
            "value": 2346,
            "unit": "B/op",
            "extra": "228645 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHit - allocs/op",
            "value": 43,
            "unit": "allocs/op",
            "extra": "228645 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME",
            "value": 5180,
            "unit": "ns/op\t    2434 B/op\t      44 allocs/op",
            "extra": "228397 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - ns/op",
            "value": 5180,
            "unit": "ns/op",
            "extra": "228397 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - B/op",
            "value": 2434,
            "unit": "B/op",
            "extra": "228397 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheHitCNAME - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "228397 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss",
            "value": 114508,
            "unit": "ns/op\t    6805 B/op\t     116 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/CacheMiss - ns/op",
            "value": 114508,
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
            "value": 4649,
            "unit": "ns/op\t    2378 B/op\t      44 allocs/op",
            "extra": "259309 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - ns/op",
            "value": 4649,
            "unit": "ns/op",
            "extra": "259309 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - B/op",
            "value": 2378,
            "unit": "B/op",
            "extra": "259309 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/Blocked - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "259309 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE",
            "value": 4885,
            "unit": "ns/op\t    2490 B/op\t      49 allocs/op",
            "extra": "236616 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - ns/op",
            "value": 4885,
            "unit": "ns/op",
            "extra": "236616 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - B/op",
            "value": 2490,
            "unit": "B/op",
            "extra": "236616 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/BlockedWithEDE - allocs/op",
            "value": 49,
            "unit": "allocs/op",
            "extra": "236616 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD",
            "value": 4854,
            "unit": "ns/op\t    2161 B/op\t      37 allocs/op",
            "extra": "245346 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - ns/op",
            "value": 4854,
            "unit": "ns/op",
            "extra": "245346 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - B/op",
            "value": 2161,
            "unit": "B/op",
            "extra": "245346 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/DNSSD - allocs/op",
            "value": 37,
            "unit": "allocs/op",
            "extra": "245346 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD",
            "value": 4353,
            "unit": "ns/op\t    2137 B/op\t      36 allocs/op",
            "extra": "270355 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - ns/op",
            "value": 4353,
            "unit": "ns/op",
            "extra": "270355 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - B/op",
            "value": 2137,
            "unit": "B/op",
            "extra": "270355 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ReservedTLD - allocs/op",
            "value": 36,
            "unit": "allocs/op",
            "extra": "270355 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions",
            "value": 119748,
            "unit": "ns/op\t    7621 B/op\t     134 allocs/op",
            "extra": "9960 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - ns/op",
            "value": 119748,
            "unit": "ns/op",
            "extra": "9960 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - B/op",
            "value": 7621,
            "unit": "B/op",
            "extra": "9960 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/MultipleQuestions - allocs/op",
            "value": 134,
            "unit": "allocs/op",
            "extra": "9960 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS",
            "value": 6526,
            "unit": "ns/op\t    3625 B/op\t      60 allocs/op",
            "extra": "183963 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - ns/op",
            "value": 6526,
            "unit": "ns/op",
            "extra": "183963 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - B/op",
            "value": 3625,
            "unit": "B/op",
            "extra": "183963 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcher/ECS - allocs/op",
            "value": 60,
            "unit": "allocs/op",
            "extra": "183963 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent",
            "value": 2927,
            "unit": "ns/op\t    2321 B/op\t      42 allocs/op",
            "extra": "381135 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - ns/op",
            "value": 2927,
            "unit": "ns/op",
            "extra": "381135 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - B/op",
            "value": 2321,
            "unit": "B/op",
            "extra": "381135 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSDispatcherConcurrent - allocs/op",
            "value": 42,
            "unit": "allocs/op",
            "extra": "381135 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get",
            "value": 168.5,
            "unit": "ns/op\t      88 B/op\t       3 allocs/op",
            "extra": "7015244 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - ns/op",
            "value": 168.5,
            "unit": "ns/op",
            "extra": "7015244 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - B/op",
            "value": 88,
            "unit": "B/op",
            "extra": "7015244 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Get - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "7015244 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set",
            "value": 465.5,
            "unit": "ns/op\t     128 B/op\t       4 allocs/op",
            "extra": "2624694 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - ns/op",
            "value": 465.5,
            "unit": "ns/op",
            "extra": "2624694 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - B/op",
            "value": 128,
            "unit": "B/op",
            "extra": "2624694 times\n4 procs"
          },
          {
            "name": "BenchmarkDNSCache/Set - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "2624694 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient",
            "value": 93669,
            "unit": "ns/op\t    3386 B/op\t      56 allocs/op",
            "extra": "12805 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - ns/op",
            "value": 93669,
            "unit": "ns/op",
            "extra": "12805 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - B/op",
            "value": 3386,
            "unit": "B/op",
            "extra": "12805 times\n4 procs"
          },
          {
            "name": "BenchmarkRoundRobinClient - allocs/op",
            "value": 56,
            "unit": "allocs/op",
            "extra": "12805 times\n4 procs"
          }
        ]
      }
    ]
  }
}