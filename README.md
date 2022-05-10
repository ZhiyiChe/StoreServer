```
.
├── go.mod
├── go.sum
├── main.go
├── protocol
│   ├── StoreServer_grpc.pb.go
│   ├── StoreServer.pb.go
│   └── StoreServer.proto
└── README.md
```

一个网络存储server，使用gRPC-Go、Protocol Buffers和gorm

## 数据库表
- 用户管理（users表）
```
- 唯一id
- userName
- password
```
- 文件管理（files表）
```
- 唯一id
- fileName
- fileType 文件类型（目录/非目录）
- userName
- COSURL // for对象存储
- fileSize 文件大小（字符串存储KB/MB/GB）
- isEncrypted 是否加密
- password 如果加密，存加密密码
- updateTime 修改日期 // 自生成
```
