/*
 *
 * Copyright 2015 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

// Package main implements a server for Servicer service.
package main

import (
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	pb "github.com/ZhiyiChe/StoreServer/protocol"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const (
	port = ":50051"
)

var db *gorm.DB = nil

// GetGormProxy 获取gorm连接
func GetGormProxy() (*gorm.DB, error) {
	if db != nil {
		return db, nil
	}
	// gorm连接mysql
	// 参考 https://github.com/go-sql-driver/mysql#dsn-data-source-name 获取详情
	dsn := "user:passwd@tcp(127.0.0.1:3306)/StoreServerDB?charset=utf8mb4&parseTime=True&loc=Local"
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Printf("gorm.Open() failed: %v \n", err)
		return nil, err
	}
	return db, err
}

// UTF8ToString 转换UTF-8字符串到中文字符串
func UTF8ToString(in string) string {
	m := map[byte]byte{
		'1': 1,
		'2': 2,
		'3': 3,
		'4': 4,
		'5': 5,
		'6': 6,
		'7': 7,
		'8': 8,
		'9': 9,
		'A': 10,
		'B': 11,
		'C': 12,
		'D': 13,
		'E': 14,
		'F': 15,
	}

	ret := []byte{}
	for i := 0; i < len(in); i += 2 {
		ret = append(ret, m[in[i]]*16+m[in[i+1]])
	}
	return string(ret)
}

// User 对应数据库users表
type User struct {
	Id       int    `gorm:"column:id;primaryKey"`
	UserName string `gorm:"column:userName"`
	Password string `gorm:"column:password"`
}

// File 对应数据库files表
type File struct {
	Id          int    `gorm:"column:id;primaryKey"`
	FileName    string `gorm:"column:fileName"`
	FileType    string `gorm:"column:fileType"`
	UserName    string `gorm:"column:userName"`
	COSURL      string `gorm:"column:COSURL"`
	FileSize    string `gorm:"column:fileSize"`
	IsEncrypted string `gorm:"column:isEncrypted"`
	Password    string `gorm:"column:password"`
	UpdateTime  string `gorm:"column:updateTime;<-:false"` // 无写入权限，插入时mysql会赋予其默认值
}

// server is used to implement helloworld.GreeterServer.
type server struct {
	pb.UnimplementedServicerServer
}

// SayHello implements helloworld.GreeterServer
func (s *server) SayHello(ctx context.Context, in *pb.HelloRequest) (*pb.HelloReply, error) {
	// p, _ := peer.FromContext(ctx) // 查看对端ip
	// fmt.Println(p.Addr.String())
	log.Printf("SayHello Received: %v", in.GetName())
	return &pb.HelloReply{Message: "Hello " + in.GetName()}, nil
}

// SayHelloAgain for test
func (s *server) SayHelloAgain(ctx context.Context, in *pb.HelloRequest) (*pb.HelloReply, error) {
	log.Printf("SayHelloAgain Received: %v", in.GetName())
	return &pb.HelloReply{Message: "Hello again " + in.GetName()}, nil
}

// RegisterUser 用户注册
func (s *server) RegisterUser(ctx context.Context, req *pb.RegisterUserRequest) (*pb.RegisterUserReply, error) {
	log.Printf("RegisterUser Received: %v", req)
	// 获取gorm连接
	db, err := GetGormProxy()
	if err != nil {
		log.Printf("GetGormProxy() failed: %v \n", err)
		return nil, err
	}

	// 获取一条匹配的记录
	user := User{}
	result := db.Where("userName = ?", req.UserName).Take(&user)

	// 如果数据库中已有该req.userName，注册失败
	if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return &pb.RegisterUserReply{Code: 1, Message: "failure"}, nil
	}

	// 把注册数据插入到db
	result = db.Create(&User{UserName: req.UserName, Password: req.Password})
	if result.Error != nil {
		return nil, result.Error
	}

	// 项目根目录创建以req.UserName为名的文件夹
	dirPath := fmt.Sprintf("./%s", req.UserName)
	err = os.Mkdir(dirPath, os.ModePerm)
	if err != nil {
		log.Printf("os.Mkdir() failed: %v \n", err)
		return nil, err
	}

	return &pb.RegisterUserReply{Code: 0, Message: "success"}, nil
}

// LoginUser 用户登录
func (s *server) LoginUser(ctx context.Context, req *pb.LoginUserRequest) (*pb.LoginUserReply, error) {
	log.Printf("LoginUser Received: %v", req)
	// 获取gorm连接
	db, err := GetGormProxy()
	if err != nil {
		log.Printf("GetGormProxy() failed: %v \n", err)
		return nil, err
	}

	// 获取一条匹配的记录
	user := User{}
	result := db.Where("userName = ?", req.UserName).Take(&user)

	// 如果数据库中没有该req.userName，或者登录密码错误，登录失败
	if errors.Is(result.Error, gorm.ErrRecordNotFound) || user.Password != req.Password {
		return &pb.LoginUserReply{Code: 1, Message: "failure"}, nil
	}

	// 登录成功
	return &pb.LoginUserReply{Code: 0, Message: "success"}, nil
}

// QueryAllFiles 查找所有文件
func (s *server) QueryAllFiles(ctx context.Context, req *pb.QueryAllFilesRequest) (*pb.QueryAllFilesReply, error) {
	log.Printf("QueryAllFiles Received: %v", req)
	// 获取gorm连接
	db, err := GetGormProxy()
	if err != nil {
		log.Printf("GetGormProxy() failed: %v \n", err)
		return nil, err
	}

	// 迭代查询所有记录
	rows, err := db.Model(&File{}).Where("userName = ?", req.UserName).Rows()
	if err != nil {
		log.Printf("db.Model() failed: %v \n", err)
		return nil, err
	}
	defer rows.Close()

	reply := pb.QueryAllFilesReply{}
	for rows.Next() {
		var file File
		db.ScanRows(rows, &file) // 将一行记录扫描至结构体
		reply.Files = append(reply.Files, &pb.QueryAllFilesReply_FileInfo{
			FileName:   file.FileName,
			FileType:   file.FileType,
			FileSize:   file.FileSize,
			UpdateTime: file.UpdateTime,
		})
	}

	return &reply, nil
}

// UploadFile 上传文件
func (s *server) UploadFile(stream pb.Servicer_UploadFileServer) error {
	log.Printf("UploadFile serving...")
	// 元数据解析
	mdata, ok := metadata.FromIncomingContext(stream.Context())
	if !ok {
		log.Printf("get metadata error")
	}

	fmt.Println("mdata['filename'][0]: ", mdata["filename"][0])
	fileName := UTF8ToString(mdata["filename"][0])
	fmt.Println("fileName: ", fileName)

	// 获取gorm连接
	db, err := GetGormProxy()
	if err != nil {
		log.Printf("GetGormProxy() failed: %v \n", err)
		return err
	}

	// 获取一条匹配的记录
	file := File{}
	result := db.Where("userName = ? AND fileName = ?", mdata["username"][0], fileName).Take(&file)

	// 如果数据库中已有该userName和fileName对应的文件，上传失败
	if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
		// once the transmission finished, send the confirmation if nothing went wrong
		err = stream.SendAndClose(&pb.UploadFileReply{
			Message: "File exists",
			Code:    1,
		})
		if err != nil {
			log.Printf("stream.SendAndClose() failed: %v \n", err)
			return err
		}
		return nil
	}

	// 写入该文件
	filePath := fmt.Sprintf("./%s/%s", mdata["username"][0], fileName)
	f, err := os.Create(filePath)
	if err != nil {
		log.Printf("os.Create() failed: %v \n", err)
		return err
	}

	// while there are messages coming
	for {
		chunk, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				goto END
			}
			log.Printf("stream.Recv() failed: %v \n", err)
			return err
		}
		// 追加写入文件
		// 查找文件末尾的偏移量
		n, err := f.Seek(0, 2)
		if err != nil {
			log.Printf("f.Seek() failed: %v \n", err)
			return err
		}
		// 从末尾的偏移量开始写入内容
		_, err = f.WriteAt(chunk.Content, n)
		if err != nil {
			log.Printf("f.WriteAt() failed: %v \n", err)
			return err
		}
	}
END:
	// 把文件数据插入到db
	result = db.Create(&File{
		FileName:    fileName,
		FileType:    mdata["filetype"][0],
		UserName:    mdata["username"][0],
		FileSize:    mdata["filesize"][0],
		IsEncrypted: mdata["isencrypted"][0],
		Password:    mdata["password"][0],
	})
	if result.Error != nil {
		log.Printf("db.Create() failed: %v \n", result.Error)
		return result.Error
	}

	// once the transmission finished, send the confirmation if nothing went wrong
	err = stream.SendAndClose(&pb.UploadFileReply{
		Message: "Upload received with success",
		Code:    0,
	})
	if err != nil {
		log.Printf("stream.SendAndClose() failed: %v \n", err)
		return err
	}

	return nil
}

// QueryFileIsEncrypted 查询文件是否加密
func (s *server) QueryFileIsEncrypted(ctx context.Context, req *pb.QueryFileIsEncryptedRequest) (*pb.QueryFileIsEncryptedReply, error) {
	log.Printf("QueryFileIsEncrypted Received: %v", req)
	// 获取gorm连接
	db, err := GetGormProxy()
	if err != nil {
		log.Printf("GetGormProxy() failed: %v \n", err)
		return nil, err
	}

	// 获取一条匹配的记录
	file := File{}
	result := db.Where("userName = ? AND fileName = ?", req.UserName, req.FileName).Take(&file)

	// 如果数据库中没有该file，返回状态码：2
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return &pb.QueryFileIsEncryptedReply{Code: 2, Message: "file not exist"}, nil
	} else if result.Error != nil {
		log.Printf("db.Where().Take() failed: %v \n", result.Error)
		return nil, result.Error
	}

	// 如果该file被加密
	if file.IsEncrypted == "1" {
		return &pb.QueryFileIsEncryptedReply{Code: 1, Message: "encrypted"}, nil
	}

	// 该file未被加密
	return &pb.QueryFileIsEncryptedReply{Code: 0, Message: "not encrypted"}, nil
}

// VerifyFilePassword 校验文件密码
func (s *server) VerifyFilePassword(ctx context.Context, req *pb.VerifyFilePasswordRequest) (*pb.VerifyFilePasswordReply, error) {
	log.Printf("VerifyFilePassword Received: %v", req)
	// 获取gorm连接
	db, err := GetGormProxy()
	if err != nil {
		log.Printf("GetGormProxy() failed: %v \n", err)
		return nil, err
	}

	// 获取一条匹配的记录
	file := File{}
	result := db.Where("userName = ? AND fileName = ? AND password = ?", req.UserName, req.FileName, req.Password).Take(&file)

	// 如果数据库中没有该file，说明密码错误，返回状态码：1
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return &pb.VerifyFilePasswordReply{Code: 1, Message: "wrong passoword"}, nil
	} else if result.Error != nil {
		log.Printf("db.Where().Take() failed: %v \n", result.Error)
		return nil, result.Error
	}

	// 密码正确
	return &pb.VerifyFilePasswordReply{Code: 0, Message: "correct passoword"}, nil
}

// DownloadFile 下载文件
func (s *server) DownloadFile(req *pb.DownloadFileRequest, stream pb.Servicer_DownloadFileServer) error {
	log.Printf("DownloadFile Received: %v", req)
	filePath := fmt.Sprintf("./%s/%s", req.UserName, req.FileName)
	f, err := os.Open(filePath)
	if err != nil {
		log.Printf("os.Open() failed: %v \n", err)
		return err
	}
	defer f.Close()

	for {
		chunk := make([]byte, 1024*128) // make([], len, [cap])
		n, err := f.Read(chunk)         // f.Read 读取文件内容到chunk中
		if err != nil {
			if err == io.EOF {
				goto END
			}
			log.Printf("f.Read() failed: %v \n", err)
			return err
		}
		// 把chunk发送到客户端
		if err := stream.Send(&pb.Chunk{Content: chunk[0:n]}); err != nil {
			return err
		}
	}
END:
	return nil
}

// DeleteFile 删除文件
func (s *server) DeleteFile(ctx context.Context, req *pb.DeleteFileRequest) (*pb.DeleteFileReply, error) {
	log.Printf("DeleteFile Received: %v", req)
	// 获取gorm连接
	db, err := GetGormProxy()
	if err != nil {
		log.Printf("GetGormProxy() failed: %v \n", err)
		return nil, err
	}

	// 删除一条匹配的记录
	db.Where("userName = ? AND fileName = ?", req.UserName, req.FileName).Delete(File{})
	return &pb.DeleteFileReply{Code: 0, Message: "success"}, nil
}

// QueryFileMd 查询文件md5
func (s *server) QueryFileMd(ctx context.Context, req *pb.QueryFileMdRequest) (*pb.QueryFileMdReply, error) {
	log.Printf("QueryFileMd Received: %v", req)
	filePath := fmt.Sprintf("./%s/%s", req.UserName, req.FileName)
	f, err := os.Open(filePath)
	if err != nil {
		log.Printf("os.Open() failed: %v \n", err)
		return nil, err
	}
	defer f.Close()

	md5hash := md5.New()
	_, err = io.Copy(md5hash, f)
	if err != nil {
		log.Printf("io.Copy() failed: %v \n", err)
		return nil, err
	}

	fileMd := fmt.Sprintf("%x", md5hash.Sum(nil))
	return &pb.QueryFileMdReply{Code: 0, Message: "success", Data: fileMd}, nil
}

func main() {
	// log打印行号
	log.SetFlags(log.Lshortfile | log.LstdFlags)

	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer()
	pb.RegisterServicerServer(s, &server{})

	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
