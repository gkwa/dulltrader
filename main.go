package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type InstanceSecurityGroups struct {
	InstanceID           string            `json:"instance_id"`
	InstanceName         string            `json:"instance_name"`
	BeforeSecurityGroups map[string]string `json:"before_security_groups"`
	AfterSecurityGroups  map[string]string `json:"after_security_groups"`
}

func main() {
	// Parse command-line flags
	pattern := flag.String("pattern", "", "Wildcard pattern for the 'Name' tag")
	region := flag.String("region", "", "AWS region")
	securityGroupTag := flag.String("security-group-tag", "", "Tag name of the security group")
	flag.Parse()

	if *pattern == "" || *region == "" || *securityGroupTag == "" {
		flag.Usage()
		os.Exit(1)
	}

	// Create a context
	ctx := context.Background()

	// Load the AWS configuration for the specified region
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(*region))
	if err != nil {
		fmt.Println("Failed to load AWS configuration:", err)
		return
	}

	// Create an EC2 client
	client := ec2.NewFromConfig(cfg)

	// Specify the tag key and wildcard pattern for the instance
	instanceTagKey := "Name"
	instanceWildcardPattern := *pattern

	// Specify the desired instance states
	instanceStates := []types.InstanceStateName{
		types.InstanceStateNameRunning,
		types.InstanceStateNamePending,
		types.InstanceStateNameStopped,
	}

	// Create the input parameters for describing instances with the specified tag and state
	instanceInput := &ec2.DescribeInstancesInput{
		Filters: []types.Filter{
			{
				Name:   awsString("tag-key"),
				Values: []string{instanceTagKey},
			},
			{
				Name:   awsString("tag-value"),
				Values: []string{instanceWildcardPattern},
			},
			{
				Name:   awsString("instance-state-name"),
				Values: instanceStateNamesToStrings(instanceStates),
			},
		},
	}

	// Describe the instances with the specified tag and state
	instanceResp, err := client.DescribeInstances(ctx, instanceInput)
	if err != nil {
		fmt.Println("Failed to describe instances:", err)
		return
	}

	var instanceSecurityGroups []InstanceSecurityGroups

	for _, reservation := range instanceResp.Reservations {
		for _, instance := range reservation.Instances {
			instanceID := *instance.InstanceId
			instanceName := getInstanceTagValue(instance.Tags, instanceTagKey)

			beforeSecurityGroups := make(map[string]string)
			afterSecurityGroups := make(map[string]string)

			for _, group := range instance.SecurityGroups {
				beforeSecurityGroups[*group.GroupId] = *group.GroupName
				afterSecurityGroups[*group.GroupId] = *group.GroupName
			}

			// Retrieve the security group ID for the provided tag name
			securityGroupID, err := getSecurityGroupIDByTag(ctx, client, *securityGroupTag)
			if err != nil {
				fmt.Println("Failed to retrieve security group ID:", err)
				return
			}

			afterSecurityGroups[*securityGroupID] = *securityGroupTag

			instanceSG := InstanceSecurityGroups{
				InstanceID:           instanceID,
				InstanceName:         instanceName,
				BeforeSecurityGroups: beforeSecurityGroups,
				AfterSecurityGroups:  afterSecurityGroups,
			}

			instanceSecurityGroups = append(instanceSecurityGroups, instanceSG)
		}
	}

	if len(instanceSecurityGroups) == 0 {
		fmt.Println("No instances found for the specified EC2 instance tag.")
		return
	}

	// Generate the output filename
	outputFilename := "dulltrader.json"
	if _, err := os.Stat(outputFilename); err == nil {
		outputFilename = addTimestampToFilename(outputFilename)
	}

	// Create a JSON file and write the results
	file, err := os.Create(outputFilename)
	if err != nil {
		fmt.Println("Failed to create JSON file:", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	err = encoder.Encode(instanceSecurityGroups)
	if err != nil {
		fmt.Println("Failed to encode JSON:", err)
		return
	}

	fmt.Printf("Results written to %s\n", outputFilename)
}

func instanceStateNamesToStrings(states []types.InstanceStateName) []string {
	var stateStrings []string
	for _, state := range states {
		stateStrings = append(stateStrings, string(state))
	}
	return stateStrings
}

func getInstanceTagValue(tags []types.Tag, key string) string {
	for _, tag := range tags {
		if *tag.Key == key {
			return *tag.Value
		}
	}
	return ""
}

func getSecurityGroupIDByTag(ctx context.Context, client *ec2.Client, tagName string) (*string, error) {
	// Create the input parameters for describing security groups with the specified tag
	input := &ec2.DescribeSecurityGroupsInput{
		Filters: []types.Filter{
			{
				Name:   awsString("tag-key"),
				Values: []string{"Name"},
			},
			{
				Name:   awsString("tag-value"),
				Values: []string{tagName},
			},
		},
	}

	// Describe the security groups with the specified tag
	resp, err := client.DescribeSecurityGroups(ctx, input)
	if err != nil {
		return nil, err
	}

	// Extract the security group ID from the response
	if len(resp.SecurityGroups) > 0 {
		return resp.SecurityGroups[0].GroupId, nil
	}

	return nil, fmt.Errorf("security group not found for tag: %s", tagName)
}

func addTimestampToFilename(filename string) string {
	timestamp := time.Now().Format("20060102150405")
	ext := ".json"
	if strings.HasSuffix(filename, ext) {
		filename = strings.TrimSuffix(filename, ext)
	}
	return filename + "-" + timestamp + ext
}

func awsString(s string) *string {
	return &s
}
