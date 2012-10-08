# encoding: UTF-8

require 'app'
require 'ap'

$r = Redis.new(:host => RedisHost, :port => RedisPort) if !$r

#ap $r.zrange("news.up:252",0,-1,:withscores => true)
#ap $r.zrevrange("news.top",0,10)[2]
#ap $r.zscore("news.up:252",1)

news = $r.pipelined {
  [252].each {|nid| $r.hgetall("news:#{nid}")}
}

ap news


# Get the associated users information
usernames = $r.pipelined {
    news.each{|n|
        $r.hget("user:#{n["user_id"]}","username")
    }
}
ap usernames

news.each_with_index{|n,i|
    n["username"] = usernames[i]
}

ap news


votes = $r.pipelined {
    news.each{|n|
        $r.zscore("news.up:#{n["id"]}",1)
        $r.zscore("news.down:#{n["id"]}",1)
    }
}

ap votes


news.each_with_index{|n,i|
  puts ">>>> #{i}"
    if votes[i*2]
        n["voted"] = :up
    elsif votes[(i*2)+1]
        n["voted"] = :down
    end
}

ap news
