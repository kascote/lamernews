# encoding: UTF-8
require 'app_config'
require 'rubygems'
require 'hiredis'
require 'redis'
require 'ap'

$r = Redis.new(:host => RedisHost, :port => RedisPort) if !$r

if !$r.exists("username.to.id:#{ARGV[0]}")
  puts  'usuario no existe'
  exit 255
end

id = $r.get("username.to.id:#{ARGV[0]}")
user = $r.hgetall("user:#{id}") # get user by id

ap user

