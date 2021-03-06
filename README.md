「認証の課題とID連携の実装」
=========

# はじめに

このソースコードは演習用を目的として作成しています。  
脆弱な実装や、演習上の理由で実装を簡潔にしているためセキュリティ上の検証が不十分な部分があります。  
そのため実際のサービス等には利用しないでください。利用した際に生じた損害等の責任は負いかねます。  

# 概要

本内容は以下の講義で実施されたID連携（OpenID Connect）ハンズオンのGolangによるサンプルコードです。

セキュリティ・キャンプ全国大会2019
* B4 認証の課題とID連携の実装
  * https://www.ipa.go.jp/jinzai/camp/2019/zenkoku2019_program_list.html#list_d3-b4

# コンテンツ

* practice00
  * Golang実行環境セットアップ
* practice01-1
  * トークン置き換え攻撃体験
* practice01-2
  * ユーザー識別子による脆弱な認証体験
* practice02
  * CSRF攻撃体験
* practice02-answer
  * CSRF攻撃対策
* practice03
  * ユーザー認証（ID Tokenの検証）・リプレイ攻撃対策
* practice03-answer
  * ID Tokenの検証・リプレイ攻撃対策
