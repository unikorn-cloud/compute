//go:build !ignore_autogenerated
// +build !ignore_autogenerated

/*
Copyright 2024 the Unikorn Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by deepcopy-gen. DO NOT EDIT.

package v1alpha1

import (
	unikornv1alpha1 "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ComputeCluster) DeepCopyInto(out *ComputeCluster) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ComputeCluster.
func (in *ComputeCluster) DeepCopy() *ComputeCluster {
	if in == nil {
		return nil
	}
	out := new(ComputeCluster)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ComputeCluster) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ComputeClusterList) DeepCopyInto(out *ComputeClusterList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]ComputeCluster, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ComputeClusterList.
func (in *ComputeClusterList) DeepCopy() *ComputeClusterList {
	if in == nil {
		return nil
	}
	out := new(ComputeClusterList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ComputeClusterList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ComputeClusterSpec) DeepCopyInto(out *ComputeClusterSpec) {
	*out = *in
	if in.Tags != nil {
		in, out := &in.Tags, &out.Tags
		*out = make(unikornv1alpha1.TagList, len(*in))
		copy(*out, *in)
	}
	if in.Network != nil {
		in, out := &in.Network, &out.Network
		*out = new(unikornv1alpha1.NetworkGeneric)
		(*in).DeepCopyInto(*out)
	}
	if in.WorkloadPools != nil {
		in, out := &in.WorkloadPools, &out.WorkloadPools
		*out = new(ComputeClusterWorkloadPoolsSpec)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ComputeClusterSpec.
func (in *ComputeClusterSpec) DeepCopy() *ComputeClusterSpec {
	if in == nil {
		return nil
	}
	out := new(ComputeClusterSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ComputeClusterStatus) DeepCopyInto(out *ComputeClusterStatus) {
	*out = *in
	if in.WorkloadPools != nil {
		in, out := &in.WorkloadPools, &out.WorkloadPools
		*out = make([]WorkloadPoolStatus, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]unikornv1alpha1.Condition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ComputeClusterStatus.
func (in *ComputeClusterStatus) DeepCopy() *ComputeClusterStatus {
	if in == nil {
		return nil
	}
	out := new(ComputeClusterStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ComputeClusterWorkloadPoolsPoolSpec) DeepCopyInto(out *ComputeClusterWorkloadPoolsPoolSpec) {
	*out = *in
	in.ComputeWorkloadPoolSpec.DeepCopyInto(&out.ComputeWorkloadPoolSpec)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ComputeClusterWorkloadPoolsPoolSpec.
func (in *ComputeClusterWorkloadPoolsPoolSpec) DeepCopy() *ComputeClusterWorkloadPoolsPoolSpec {
	if in == nil {
		return nil
	}
	out := new(ComputeClusterWorkloadPoolsPoolSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ComputeClusterWorkloadPoolsSpec) DeepCopyInto(out *ComputeClusterWorkloadPoolsSpec) {
	*out = *in
	if in.Pools != nil {
		in, out := &in.Pools, &out.Pools
		*out = make([]ComputeClusterWorkloadPoolsPoolSpec, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ComputeClusterWorkloadPoolsSpec.
func (in *ComputeClusterWorkloadPoolsSpec) DeepCopy() *ComputeClusterWorkloadPoolsSpec {
	if in == nil {
		return nil
	}
	out := new(ComputeClusterWorkloadPoolsSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ComputeWorkloadPoolSpec) DeepCopyInto(out *ComputeWorkloadPoolSpec) {
	*out = *in
	in.MachineGeneric.DeepCopyInto(&out.MachineGeneric)
	if in.PublicIPAllocation != nil {
		in, out := &in.PublicIPAllocation, &out.PublicIPAllocation
		*out = new(PublicIPAllocationSpec)
		**out = **in
	}
	if in.Firewall != nil {
		in, out := &in.Firewall, &out.Firewall
		*out = new(FirewallSpec)
		(*in).DeepCopyInto(*out)
	}
	if in.UserData != nil {
		in, out := &in.UserData, &out.UserData
		*out = make([]byte, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ComputeWorkloadPoolSpec.
func (in *ComputeWorkloadPoolSpec) DeepCopy() *ComputeWorkloadPoolSpec {
	if in == nil {
		return nil
	}
	out := new(ComputeWorkloadPoolSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FirewallRule) DeepCopyInto(out *FirewallRule) {
	*out = *in
	in.CIDR.DeepCopyInto(&out.CIDR)
	in.Port.DeepCopyInto(&out.Port)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FirewallRule.
func (in *FirewallRule) DeepCopy() *FirewallRule {
	if in == nil {
		return nil
	}
	out := new(FirewallRule)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FirewallRulePort) DeepCopyInto(out *FirewallRulePort) {
	*out = *in
	if in.Number != nil {
		in, out := &in.Number, &out.Number
		*out = new(int)
		**out = **in
	}
	if in.Range != nil {
		in, out := &in.Range, &out.Range
		*out = new(FirewallRulePortRange)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FirewallRulePort.
func (in *FirewallRulePort) DeepCopy() *FirewallRulePort {
	if in == nil {
		return nil
	}
	out := new(FirewallRulePort)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FirewallRulePortRange) DeepCopyInto(out *FirewallRulePortRange) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FirewallRulePortRange.
func (in *FirewallRulePortRange) DeepCopy() *FirewallRulePortRange {
	if in == nil {
		return nil
	}
	out := new(FirewallRulePortRange)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FirewallSpec) DeepCopyInto(out *FirewallSpec) {
	*out = *in
	if in.Ingress != nil {
		in, out := &in.Ingress, &out.Ingress
		*out = make([]FirewallRule, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FirewallSpec.
func (in *FirewallSpec) DeepCopy() *FirewallSpec {
	if in == nil {
		return nil
	}
	out := new(FirewallSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *MachineStatus) DeepCopyInto(out *MachineStatus) {
	*out = *in
	if in.PrivateIP != nil {
		in, out := &in.PrivateIP, &out.PrivateIP
		*out = new(string)
		**out = **in
	}
	if in.PublicIP != nil {
		in, out := &in.PublicIP, &out.PublicIP
		*out = new(string)
		**out = **in
	}
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]unikornv1alpha1.Condition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new MachineStatus.
func (in *MachineStatus) DeepCopy() *MachineStatus {
	if in == nil {
		return nil
	}
	out := new(MachineStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PublicIPAllocationSpec) DeepCopyInto(out *PublicIPAllocationSpec) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PublicIPAllocationSpec.
func (in *PublicIPAllocationSpec) DeepCopy() *PublicIPAllocationSpec {
	if in == nil {
		return nil
	}
	out := new(PublicIPAllocationSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *WorkloadPoolStatus) DeepCopyInto(out *WorkloadPoolStatus) {
	*out = *in
	if in.Machines != nil {
		in, out := &in.Machines, &out.Machines
		*out = make([]MachineStatus, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WorkloadPoolStatus.
func (in *WorkloadPoolStatus) DeepCopy() *WorkloadPoolStatus {
	if in == nil {
		return nil
	}
	out := new(WorkloadPoolStatus)
	in.DeepCopyInto(out)
	return out
}
