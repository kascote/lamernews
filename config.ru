
ROOT_DIR = File.expand_path(File.dirname(__FILE__))
$: << ROOT_DIR

require 'rubygems'
require 'sinatra'
require 'app.rb'

run Sinatra::Application
