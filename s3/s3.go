package s3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/fgiamma/gocommons"
)

type S3Data struct {
	AwsAccessKeyId     string `json:"aws_access_key_id"`
	AwsSecretAccessKey string `json:"aws_secret_access_key"`
	AwsRegionName      string `json:"aws_region_name"`
	AwsBucketName      string `json:"aws_bucket_name"`
}

type DoS3Data struct {
	AccessKey  string `json:"access_key"`
	Secret     string `json:"secret"`
	Region     string `json:"region"`
	SpacesUrl  string `json:"spaces_url"`
	BucketName string `json:"bucket_name"`
}

type S3PutObjectAPI interface {
	PutObject(ctx context.Context,
		params *s3.PutObjectInput,
		optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

func PutFile(c context.Context, api S3PutObjectAPI, input *s3.PutObjectInput) (*s3.PutObjectOutput, error) {
	return api.PutObject(c, input)
}

func SendToS3(s3data S3Data, objectName string) error {
	cfg, err := config.LoadDefaultConfig(
		context.TODO(), config.WithRegion(s3data.AwsRegionName),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(s3data.AwsAccessKeyId, s3data.AwsSecretAccessKey, "")))

	if err != nil {
		return errors.New("can't connect to Amazon S3")
	}

	// Create an Amazon S3 service client
	client := s3.NewFromConfig(cfg)

	file, err := os.Open("/tmp/" + objectName)

	if err != nil {
		return errors.New("unable to open file")
	}

	defer file.Close()

	input := &s3.PutObjectInput{
		Bucket: &s3data.AwsBucketName,
		Key:    &objectName,
		Body:   file,
	}

	_, err = PutFile(context.TODO(), client, input)
	if err != nil {
		return errors.New("unable to upload file")
	}

	return nil
}

func DownloadFromS3(s3data S3Data, objectName string) (string, error) {
	cfg, err := config.LoadDefaultConfig(
		context.TODO(), config.WithRegion(s3data.AwsRegionName),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(s3data.AwsAccessKeyId, s3data.AwsSecretAccessKey, "")))

	if err != nil {
		return "", errors.New("can't connect to Amazon S3")
	}

	// Create an Amazon S3 service client
	client := s3.NewFromConfig(cfg)

	result, err := client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String(s3data.AwsBucketName),
		Key:    aws.String(objectName),
	})

	if err != nil {
		return "", err
	}

	pointPosition := strings.LastIndex(objectName, ".")
	extension := objectName[pointPosition:]

	fileName := fmt.Sprintf("/tmp/%s%s", gocommons.GetUid(), extension)

	defer result.Body.Close()
	file, err := os.Create(fileName)
	if err != nil {
		return "", err
	}
	defer file.Close()
	body, err := io.ReadAll(result.Body)
	if err != nil {
		return "", err
	}
	_, err = file.Write(body)

	if err != nil {
		return "", err
	}

	return fileName, nil
}

type S3DeleteObjectAPI interface {
	DeleteObject(ctx context.Context,
		params *s3.DeleteObjectInput,
		optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
}

// DeleteItem deletes an object from an Amazon Simple Storage Service (Amazon S3) bucket
// Inputs:
//
//	c is the context of the method call, which includes the AWS Region
//	api is the interface that defines the method call
//	input defines the input arguments to the service call.
//
// Output:
//
//	If success, a DeleteObjectOutput object containing the result of the service call and nil
//	Otherwise, an error from the call to DeleteObject
func DeleteS3Item(c context.Context, api S3DeleteObjectAPI, input *s3.DeleteObjectInput) (*s3.DeleteObjectOutput, error) {
	return api.DeleteObject(c, input)
}

func DeleteFromS3(s3data S3Data, objectName string) error {
	cfg, err := config.LoadDefaultConfig(
		context.TODO(), config.WithRegion(s3data.AwsRegionName),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(s3data.AwsAccessKeyId, s3data.AwsSecretAccessKey, "")))

	if err != nil {
		return errors.New("can't connect to Amazon S3")
	}

	// Create an Amazon S3 service client
	client := s3.NewFromConfig(cfg)

	// client.DeleteObject()

	input := &s3.DeleteObjectInput{
		Bucket: &s3data.AwsBucketName,
		Key:    &objectName,
	}

	_, err = DeleteS3Item(context.TODO(), client, input)
	if err != nil {
		return err
	}

	return nil
}

func DeleteFromDoS3(s3data DoS3Data, objectName string) error {
	// Create a custom resolver for DigitalOcean Spaces
	customResolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
		return aws.Endpoint{
			URL: s3data.SpacesUrl,
		}, nil
	})

	// Configure the AWS SDK
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(s3data.Region),
		config.WithEndpointResolverWithOptions(customResolver),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(s3data.AccessKey, s3data.Secret, "")),
	)
	if err != nil {
		return err
	}

	// Create an Amazon S3 service client
	client := s3.NewFromConfig(cfg)

	// client.DeleteObject()

	input := &s3.DeleteObjectInput{
		Bucket: &s3data.BucketName,
		Key:    &objectName,
	}

	_, err = DeleteS3Item(context.TODO(), client, input)
	if err != nil {
		return err
	}

	return nil
}

func DownloadFromDoS3(s3data DoS3Data, objectName string) (string, error) {
	// Create a custom resolver for DigitalOcean Spaces
	customResolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
		return aws.Endpoint{
			URL: s3data.SpacesUrl,
		}, nil
	})

	// Configure the AWS SDK
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(s3data.Region),
		config.WithEndpointResolverWithOptions(customResolver),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(s3data.AccessKey, s3data.Secret, "")),
	)
	if err != nil {
		return "", err
	}
	// Create an Amazon S3 service client
	client := s3.NewFromConfig(cfg)

	result, err := client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String(s3data.BucketName),
		Key:    aws.String(objectName),
	})

	if err != nil {
		return "", err
	}

	pointPosition := strings.LastIndex(objectName, ".")
	extension := objectName[pointPosition:]

	fileName := fmt.Sprintf("/tmp/%s%s", gocommons.GetUid(), extension)

	defer result.Body.Close()
	file, err := os.Create(fileName)
	if err != nil {
		return "", err
	}
	defer file.Close()
	body, err := io.ReadAll(result.Body)
	if err != nil {
		return "", err
	}
	_, err = file.Write(body)

	if err != nil {
		return "", err
	}

	return fileName, nil
}
