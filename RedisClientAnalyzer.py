# Copyright (c) 2015, Fundacion Dr. Manuel Sadosky
# All rights reserved.

# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:

# 1. Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.

# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.

# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


from Utils import *


class RedisClientAnalyzer(VulnerabilityAnalyzer):
    def __init__(self, vm, dx, cm):
        super(RedisClientAnalyzer, self).__init__()
        self.vm = vm
        self.dx = dx
        self.cm = cm

    def warning_of(self, library):
        description = "%s was found, this library is not suited for mobile applications since the Redis framework only has one user and the application needs to be given access to the users credentials\n" % library
        self.add_vulnerability("REDIS", description)

    def check_redis_client(self):

        if self.dx.tainted_packages.search_packages("Lredis/clients/jedis/"):
            self.warning_of("Jedis")

        if self.dx.tainted_packages.search_packages("Lorg/jredis/"):
            self.warning_of("Jedis")

        if self.dx.tainted_packages.search_packages("Lbr/com/svvs.jdbc.redis/"):
            self.warning_of("JDBC-Redis")

        if self.dx.tainted_packages.search_packages("Lorg/redisson/"):
            self.warning_of("Jedis")

        if self.dx.tainted_packages.search_packages("Lcom/github/spullara/redis/"):
            self.warning_of("Redis-protocol")

        if self.dx.tainted_packages.search_packages("Lcom/lambdaworks/redis/"):
            self.warning_of("Lettuce Redis")

        if self.dx.tainted_packages.search_packages("Lorg/idevlab/rjc/"):
            self.warning_of("RJC Redis")

        return self.get_report()