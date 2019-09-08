Golang実行環境セットアップ
=========

以下の手順に従い環境のセットアップを行い`server.go`を実行して動作確認をしてください。

# Golangインストール

* https://golang.org/dl/

## Windows

以下の.msiをダウンロードしインストーラーに従いインストールする

* https://dl.google.com/go/go1.12.8.windows-amd64.msi

ログインユーザーのホームフォルダーに「go」フォルダーを作成

環境変数の設定

検索ボックス > 環境変数
Pathに「C:¥Go¥bin;」を追加
GOPATHを作成し「%HOME%¥go」を設定

コマンドプロンプト上で以下のコマンドでバージョンが確認できたらインストール完了

```
> go version
go version go1.12.8 widows/amd64
```

## macOS

以下の.pkgをダウンロードしインストーラーに従いインストールする

* https://dl.google.com/go/go1.12.8.darwin-amd64.pkg

ターミナルを開いている場合にはターミナルを再起動する

環境変数の設定

```
$ mkdir $HOME/go
$ export GOPATH=$HOME/go
$ export PATH=$PATH:$GOPATH/bin
```

以下は.bash_profileまたは.bashrcに追記しておくとログイン時に環境変数が設定される

```
$ export GOPATH=$HOME/go
$ export PATH=$PATH:$GOPATH/bin
```

ターミナル上で以下のコマンドでバージョンが確認できたらインストール完了

```
$ go version
go version go1.12.8 darwin/amd64
```

# サンプルWebアプリケーション実行

`$HOME/go/src/practice00/`のディレクトリーを作成

ソースコードをserver.goを保存

以下でビルドし、Webアプリケーションを実行

```
$ go build
$ ./practice00
```

ブラウザーを起動し以下が表示されたら完了

* http://localhost:8080/index

```
Hello OpenID Connect!
```
