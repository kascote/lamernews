# encoding: UTF-8
require 'app_config'
require 'rubygems'
require 'hiredis'
require 'redis'
require 'openssl'


$r = Redis.new(:host => RedisHost, :port => RedisPort) if !$r

# ID de la noticia
nid = ARGV[0]

puts "news:#{nid}"
news = $r.hgetall("news:#{nid}")
user = $r.hgetall("user:#{news['user_id']}")

puts "user: #{news['user_id']}"
puts "url: #{news['url']}"
hs = OpenSSL::Digest::SHA1.new(news['url']).to_s
puts "news:url: #{$r.sismember('news:url', hs)}"

$r.zrem('news.cron', nid)
$r.zrem('news.top', nid)
$r.zremrangebyscore("user.posted:#{nid}", '-inf', '+inf')
#$r.srem("news:url", hs) # se quita asi no pueden volver a spamear esta url
#$r.del("url:"+news['url'])
# lo quitamos de las noticias
$r.del "news:#{nid}"


$r.del("auth:#{user['auth']}")
$r.del("user:#{user['id']}")
$r.del("username.to.id:#{user['username']}")
