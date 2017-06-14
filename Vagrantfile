# -*- mode: ruby -*-
# vi: set ft=ruby :

# All Vagrant configuration is done below. The "2" in Vagrant.configure
# configures the configuration version (we support older styles for
# backwards compatibility). Please don't change it unless you know what
# you're doing.
Vagrant.configure("2") do |config|
 config.ssh.insert_key = false

  config.vm.provider "virtualbox" do |v|
    v.memory = 1024
    v.cpus = 2
  end

  (1..2).each do |i| 
    config.vm.define "CCM#{i}" do |vagrant1| 
      vagrant1.vm.box = "centos/7"
      vagrant1.vm.network "public_network", bridge: "en6"
    end
  end

  (1..2).each do |i|
    config.vm.define "CCMDB#{i}" do |vagrant2| 
      vagrant2.vm.box = "centos/7"
      vagrant2.vm.network "public_network", bridge: "en6"
    end
  end


#  config.vm.define "CCMONITOR" do |vagrant3| 
#    vagrant3.vm.box = "centos/7"
#    vagrant3.vm.network "public_network", bridge: "en6"
#  end


  config.vm.define "CCMLB" do |vagrant4| 
    vagrant4.vm.box = "centos/7"
    vagrant4.vm.network "public_network", bridge: "en6"
  end



#  config.vm.define "CCO" do |vagrant3| 
#    vagrant3.vm.box = "centos/7"
#    vagrant3.vm.network "public_network", bridge: "en6"
#  end


#  config.vm.define "AMPQ" do |vagrant4| 
#    vagrant4.vm.box = "centos/7"
#    vagrant4.vm.network "public_network", bridge: "en6"
#  end




end
