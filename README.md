# Vault Automation Client
![Build Status](https://github.com/wrouesnel/vault-automation-client/actions/workflows/release.yml/badge.svg?branch=main)
[![Coverage Status](https://coveralls.io/repos/github/wrouesnel/vault-automation-client/badge.svg?branch=main)](https://coveralls.io/github/wrouesnel/vault-automation-client?branch=main)
[![Go Report Card](https://goreportcard.com/badge/github.com/wrouesnel/vault-automation-client)](https://goreportcard.com/report/github.com/wrouesnel/vault-automation-client)

A daemon for automating Vault cluster initialization, sealing and unsealing.

This primarily implements the `unsealer` command which will watch a
given Vault instances common API address and a specific instance address
and automatically unseal and raft join new instances to an existing cluster.

Raft join and unseal modes are optional and can be disabled individually,
the most common being to disable the Raft join by setting `--initialize=false`
for when you are using a cluster or single instance.

The `unsealer` can optionally have a simple HTTP web server started on
port 8080 which implements the `/-/live`, `/-/ready` and `/-/started` endpoints suitable
direct monitoring of the service on Kubernetes. This is enabled by default
when using the Docker image of the application.

* `/-/live` returns the current timestamp that the monitoring loop last reported
* `/-/ready` returns the current timestamp the request was received
* `/-/started` returns the same as live