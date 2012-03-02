# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "quick_auth/version"

Gem::Specification.new do |s|
  s.name        = "quick_auth"
  s.version     = QuickAuth::VERSION
  s.authors     = ["Alan Graham"]
  s.email       = ["alangraham5@gmail.com"]
  s.homepage    = ""
  s.summary     = %q{Gem for backend authorization}
  s.description = %q{Gem for backend authorization}

  s.rubyforge_project = "quick_auth"

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]

  # specify any dependencies here; for example:
  # s.add_development_dependency "rspec"
  # s.add_runtime_dependency "rest-client"
end
