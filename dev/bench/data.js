window.BENCHMARK_DATA = {
  "lastUpdate": 1784997645478,
  "repoUrl": "https://github.com/rm-hull/dot-block",
  "entries": {
    "DoT Block Benchmark": [
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
      }
    ]
  }
}