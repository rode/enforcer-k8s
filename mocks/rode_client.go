// Code generated by counterfeiter. DO NOT EDIT.
package mocks

import (
	"context"
	"sync"

	"github.com/rode/rode/proto/v1alpha1"
	"github.com/rode/rode/protodeps/grafeas/proto/v1beta1/grafeas_go_proto"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

type FakeRodeClient struct {
	BatchCreateOccurrencesStub        func(context.Context, *v1alpha1.BatchCreateOccurrencesRequest, ...grpc.CallOption) (*v1alpha1.BatchCreateOccurrencesResponse, error)
	batchCreateOccurrencesMutex       sync.RWMutex
	batchCreateOccurrencesArgsForCall []struct {
		arg1 context.Context
		arg2 *v1alpha1.BatchCreateOccurrencesRequest
		arg3 []grpc.CallOption
	}
	batchCreateOccurrencesReturns struct {
		result1 *v1alpha1.BatchCreateOccurrencesResponse
		result2 error
	}
	batchCreateOccurrencesReturnsOnCall map[int]struct {
		result1 *v1alpha1.BatchCreateOccurrencesResponse
		result2 error
	}
	CreatePolicyStub        func(context.Context, *v1alpha1.PolicyEntity, ...grpc.CallOption) (*v1alpha1.Policy, error)
	createPolicyMutex       sync.RWMutex
	createPolicyArgsForCall []struct {
		arg1 context.Context
		arg2 *v1alpha1.PolicyEntity
		arg3 []grpc.CallOption
	}
	createPolicyReturns struct {
		result1 *v1alpha1.Policy
		result2 error
	}
	createPolicyReturnsOnCall map[int]struct {
		result1 *v1alpha1.Policy
		result2 error
	}
	DeletePolicyStub        func(context.Context, *v1alpha1.DeletePolicyRequest, ...grpc.CallOption) (*emptypb.Empty, error)
	deletePolicyMutex       sync.RWMutex
	deletePolicyArgsForCall []struct {
		arg1 context.Context
		arg2 *v1alpha1.DeletePolicyRequest
		arg3 []grpc.CallOption
	}
	deletePolicyReturns struct {
		result1 *emptypb.Empty
		result2 error
	}
	deletePolicyReturnsOnCall map[int]struct {
		result1 *emptypb.Empty
		result2 error
	}
	EvaluatePolicyStub        func(context.Context, *v1alpha1.EvaluatePolicyRequest, ...grpc.CallOption) (*v1alpha1.EvaluatePolicyResponse, error)
	evaluatePolicyMutex       sync.RWMutex
	evaluatePolicyArgsForCall []struct {
		arg1 context.Context
		arg2 *v1alpha1.EvaluatePolicyRequest
		arg3 []grpc.CallOption
	}
	evaluatePolicyReturns struct {
		result1 *v1alpha1.EvaluatePolicyResponse
		result2 error
	}
	evaluatePolicyReturnsOnCall map[int]struct {
		result1 *v1alpha1.EvaluatePolicyResponse
		result2 error
	}
	GetPolicyStub        func(context.Context, *v1alpha1.GetPolicyRequest, ...grpc.CallOption) (*v1alpha1.Policy, error)
	getPolicyMutex       sync.RWMutex
	getPolicyArgsForCall []struct {
		arg1 context.Context
		arg2 *v1alpha1.GetPolicyRequest
		arg3 []grpc.CallOption
	}
	getPolicyReturns struct {
		result1 *v1alpha1.Policy
		result2 error
	}
	getPolicyReturnsOnCall map[int]struct {
		result1 *v1alpha1.Policy
		result2 error
	}
	ListGenericResourcesStub        func(context.Context, *v1alpha1.ListGenericResourcesRequest, ...grpc.CallOption) (*v1alpha1.ListGenericResourcesResponse, error)
	listGenericResourcesMutex       sync.RWMutex
	listGenericResourcesArgsForCall []struct {
		arg1 context.Context
		arg2 *v1alpha1.ListGenericResourcesRequest
		arg3 []grpc.CallOption
	}
	listGenericResourcesReturns struct {
		result1 *v1alpha1.ListGenericResourcesResponse
		result2 error
	}
	listGenericResourcesReturnsOnCall map[int]struct {
		result1 *v1alpha1.ListGenericResourcesResponse
		result2 error
	}
	ListOccurrencesStub        func(context.Context, *v1alpha1.ListOccurrencesRequest, ...grpc.CallOption) (*v1alpha1.ListOccurrencesResponse, error)
	listOccurrencesMutex       sync.RWMutex
	listOccurrencesArgsForCall []struct {
		arg1 context.Context
		arg2 *v1alpha1.ListOccurrencesRequest
		arg3 []grpc.CallOption
	}
	listOccurrencesReturns struct {
		result1 *v1alpha1.ListOccurrencesResponse
		result2 error
	}
	listOccurrencesReturnsOnCall map[int]struct {
		result1 *v1alpha1.ListOccurrencesResponse
		result2 error
	}
	ListPoliciesStub        func(context.Context, *v1alpha1.ListPoliciesRequest, ...grpc.CallOption) (*v1alpha1.ListPoliciesResponse, error)
	listPoliciesMutex       sync.RWMutex
	listPoliciesArgsForCall []struct {
		arg1 context.Context
		arg2 *v1alpha1.ListPoliciesRequest
		arg3 []grpc.CallOption
	}
	listPoliciesReturns struct {
		result1 *v1alpha1.ListPoliciesResponse
		result2 error
	}
	listPoliciesReturnsOnCall map[int]struct {
		result1 *v1alpha1.ListPoliciesResponse
		result2 error
	}
	ListResourcesStub        func(context.Context, *v1alpha1.ListResourcesRequest, ...grpc.CallOption) (*v1alpha1.ListResourcesResponse, error)
	listResourcesMutex       sync.RWMutex
	listResourcesArgsForCall []struct {
		arg1 context.Context
		arg2 *v1alpha1.ListResourcesRequest
		arg3 []grpc.CallOption
	}
	listResourcesReturns struct {
		result1 *v1alpha1.ListResourcesResponse
		result2 error
	}
	listResourcesReturnsOnCall map[int]struct {
		result1 *v1alpha1.ListResourcesResponse
		result2 error
	}
	UpdateOccurrenceStub        func(context.Context, *v1alpha1.UpdateOccurrenceRequest, ...grpc.CallOption) (*grafeas_go_proto.Occurrence, error)
	updateOccurrenceMutex       sync.RWMutex
	updateOccurrenceArgsForCall []struct {
		arg1 context.Context
		arg2 *v1alpha1.UpdateOccurrenceRequest
		arg3 []grpc.CallOption
	}
	updateOccurrenceReturns struct {
		result1 *grafeas_go_proto.Occurrence
		result2 error
	}
	updateOccurrenceReturnsOnCall map[int]struct {
		result1 *grafeas_go_proto.Occurrence
		result2 error
	}
	UpdatePolicyStub        func(context.Context, *v1alpha1.UpdatePolicyRequest, ...grpc.CallOption) (*v1alpha1.Policy, error)
	updatePolicyMutex       sync.RWMutex
	updatePolicyArgsForCall []struct {
		arg1 context.Context
		arg2 *v1alpha1.UpdatePolicyRequest
		arg3 []grpc.CallOption
	}
	updatePolicyReturns struct {
		result1 *v1alpha1.Policy
		result2 error
	}
	updatePolicyReturnsOnCall map[int]struct {
		result1 *v1alpha1.Policy
		result2 error
	}
	ValidatePolicyStub        func(context.Context, *v1alpha1.ValidatePolicyRequest, ...grpc.CallOption) (*v1alpha1.ValidatePolicyResponse, error)
	validatePolicyMutex       sync.RWMutex
	validatePolicyArgsForCall []struct {
		arg1 context.Context
		arg2 *v1alpha1.ValidatePolicyRequest
		arg3 []grpc.CallOption
	}
	validatePolicyReturns struct {
		result1 *v1alpha1.ValidatePolicyResponse
		result2 error
	}
	validatePolicyReturnsOnCall map[int]struct {
		result1 *v1alpha1.ValidatePolicyResponse
		result2 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *FakeRodeClient) BatchCreateOccurrences(arg1 context.Context, arg2 *v1alpha1.BatchCreateOccurrencesRequest, arg3 ...grpc.CallOption) (*v1alpha1.BatchCreateOccurrencesResponse, error) {
	fake.batchCreateOccurrencesMutex.Lock()
	ret, specificReturn := fake.batchCreateOccurrencesReturnsOnCall[len(fake.batchCreateOccurrencesArgsForCall)]
	fake.batchCreateOccurrencesArgsForCall = append(fake.batchCreateOccurrencesArgsForCall, struct {
		arg1 context.Context
		arg2 *v1alpha1.BatchCreateOccurrencesRequest
		arg3 []grpc.CallOption
	}{arg1, arg2, arg3})
	stub := fake.BatchCreateOccurrencesStub
	fakeReturns := fake.batchCreateOccurrencesReturns
	fake.recordInvocation("BatchCreateOccurrences", []interface{}{arg1, arg2, arg3})
	fake.batchCreateOccurrencesMutex.Unlock()
	if stub != nil {
		return stub(arg1, arg2, arg3...)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *FakeRodeClient) BatchCreateOccurrencesCallCount() int {
	fake.batchCreateOccurrencesMutex.RLock()
	defer fake.batchCreateOccurrencesMutex.RUnlock()
	return len(fake.batchCreateOccurrencesArgsForCall)
}

func (fake *FakeRodeClient) BatchCreateOccurrencesCalls(stub func(context.Context, *v1alpha1.BatchCreateOccurrencesRequest, ...grpc.CallOption) (*v1alpha1.BatchCreateOccurrencesResponse, error)) {
	fake.batchCreateOccurrencesMutex.Lock()
	defer fake.batchCreateOccurrencesMutex.Unlock()
	fake.BatchCreateOccurrencesStub = stub
}

func (fake *FakeRodeClient) BatchCreateOccurrencesArgsForCall(i int) (context.Context, *v1alpha1.BatchCreateOccurrencesRequest, []grpc.CallOption) {
	fake.batchCreateOccurrencesMutex.RLock()
	defer fake.batchCreateOccurrencesMutex.RUnlock()
	argsForCall := fake.batchCreateOccurrencesArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2, argsForCall.arg3
}

func (fake *FakeRodeClient) BatchCreateOccurrencesReturns(result1 *v1alpha1.BatchCreateOccurrencesResponse, result2 error) {
	fake.batchCreateOccurrencesMutex.Lock()
	defer fake.batchCreateOccurrencesMutex.Unlock()
	fake.BatchCreateOccurrencesStub = nil
	fake.batchCreateOccurrencesReturns = struct {
		result1 *v1alpha1.BatchCreateOccurrencesResponse
		result2 error
	}{result1, result2}
}

func (fake *FakeRodeClient) BatchCreateOccurrencesReturnsOnCall(i int, result1 *v1alpha1.BatchCreateOccurrencesResponse, result2 error) {
	fake.batchCreateOccurrencesMutex.Lock()
	defer fake.batchCreateOccurrencesMutex.Unlock()
	fake.BatchCreateOccurrencesStub = nil
	if fake.batchCreateOccurrencesReturnsOnCall == nil {
		fake.batchCreateOccurrencesReturnsOnCall = make(map[int]struct {
			result1 *v1alpha1.BatchCreateOccurrencesResponse
			result2 error
		})
	}
	fake.batchCreateOccurrencesReturnsOnCall[i] = struct {
		result1 *v1alpha1.BatchCreateOccurrencesResponse
		result2 error
	}{result1, result2}
}

func (fake *FakeRodeClient) CreatePolicy(arg1 context.Context, arg2 *v1alpha1.PolicyEntity, arg3 ...grpc.CallOption) (*v1alpha1.Policy, error) {
	fake.createPolicyMutex.Lock()
	ret, specificReturn := fake.createPolicyReturnsOnCall[len(fake.createPolicyArgsForCall)]
	fake.createPolicyArgsForCall = append(fake.createPolicyArgsForCall, struct {
		arg1 context.Context
		arg2 *v1alpha1.PolicyEntity
		arg3 []grpc.CallOption
	}{arg1, arg2, arg3})
	stub := fake.CreatePolicyStub
	fakeReturns := fake.createPolicyReturns
	fake.recordInvocation("CreatePolicy", []interface{}{arg1, arg2, arg3})
	fake.createPolicyMutex.Unlock()
	if stub != nil {
		return stub(arg1, arg2, arg3...)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *FakeRodeClient) CreatePolicyCallCount() int {
	fake.createPolicyMutex.RLock()
	defer fake.createPolicyMutex.RUnlock()
	return len(fake.createPolicyArgsForCall)
}

func (fake *FakeRodeClient) CreatePolicyCalls(stub func(context.Context, *v1alpha1.PolicyEntity, ...grpc.CallOption) (*v1alpha1.Policy, error)) {
	fake.createPolicyMutex.Lock()
	defer fake.createPolicyMutex.Unlock()
	fake.CreatePolicyStub = stub
}

func (fake *FakeRodeClient) CreatePolicyArgsForCall(i int) (context.Context, *v1alpha1.PolicyEntity, []grpc.CallOption) {
	fake.createPolicyMutex.RLock()
	defer fake.createPolicyMutex.RUnlock()
	argsForCall := fake.createPolicyArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2, argsForCall.arg3
}

func (fake *FakeRodeClient) CreatePolicyReturns(result1 *v1alpha1.Policy, result2 error) {
	fake.createPolicyMutex.Lock()
	defer fake.createPolicyMutex.Unlock()
	fake.CreatePolicyStub = nil
	fake.createPolicyReturns = struct {
		result1 *v1alpha1.Policy
		result2 error
	}{result1, result2}
}

func (fake *FakeRodeClient) CreatePolicyReturnsOnCall(i int, result1 *v1alpha1.Policy, result2 error) {
	fake.createPolicyMutex.Lock()
	defer fake.createPolicyMutex.Unlock()
	fake.CreatePolicyStub = nil
	if fake.createPolicyReturnsOnCall == nil {
		fake.createPolicyReturnsOnCall = make(map[int]struct {
			result1 *v1alpha1.Policy
			result2 error
		})
	}
	fake.createPolicyReturnsOnCall[i] = struct {
		result1 *v1alpha1.Policy
		result2 error
	}{result1, result2}
}

func (fake *FakeRodeClient) DeletePolicy(arg1 context.Context, arg2 *v1alpha1.DeletePolicyRequest, arg3 ...grpc.CallOption) (*emptypb.Empty, error) {
	fake.deletePolicyMutex.Lock()
	ret, specificReturn := fake.deletePolicyReturnsOnCall[len(fake.deletePolicyArgsForCall)]
	fake.deletePolicyArgsForCall = append(fake.deletePolicyArgsForCall, struct {
		arg1 context.Context
		arg2 *v1alpha1.DeletePolicyRequest
		arg3 []grpc.CallOption
	}{arg1, arg2, arg3})
	stub := fake.DeletePolicyStub
	fakeReturns := fake.deletePolicyReturns
	fake.recordInvocation("DeletePolicy", []interface{}{arg1, arg2, arg3})
	fake.deletePolicyMutex.Unlock()
	if stub != nil {
		return stub(arg1, arg2, arg3...)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *FakeRodeClient) DeletePolicyCallCount() int {
	fake.deletePolicyMutex.RLock()
	defer fake.deletePolicyMutex.RUnlock()
	return len(fake.deletePolicyArgsForCall)
}

func (fake *FakeRodeClient) DeletePolicyCalls(stub func(context.Context, *v1alpha1.DeletePolicyRequest, ...grpc.CallOption) (*emptypb.Empty, error)) {
	fake.deletePolicyMutex.Lock()
	defer fake.deletePolicyMutex.Unlock()
	fake.DeletePolicyStub = stub
}

func (fake *FakeRodeClient) DeletePolicyArgsForCall(i int) (context.Context, *v1alpha1.DeletePolicyRequest, []grpc.CallOption) {
	fake.deletePolicyMutex.RLock()
	defer fake.deletePolicyMutex.RUnlock()
	argsForCall := fake.deletePolicyArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2, argsForCall.arg3
}

func (fake *FakeRodeClient) DeletePolicyReturns(result1 *emptypb.Empty, result2 error) {
	fake.deletePolicyMutex.Lock()
	defer fake.deletePolicyMutex.Unlock()
	fake.DeletePolicyStub = nil
	fake.deletePolicyReturns = struct {
		result1 *emptypb.Empty
		result2 error
	}{result1, result2}
}

func (fake *FakeRodeClient) DeletePolicyReturnsOnCall(i int, result1 *emptypb.Empty, result2 error) {
	fake.deletePolicyMutex.Lock()
	defer fake.deletePolicyMutex.Unlock()
	fake.DeletePolicyStub = nil
	if fake.deletePolicyReturnsOnCall == nil {
		fake.deletePolicyReturnsOnCall = make(map[int]struct {
			result1 *emptypb.Empty
			result2 error
		})
	}
	fake.deletePolicyReturnsOnCall[i] = struct {
		result1 *emptypb.Empty
		result2 error
	}{result1, result2}
}

func (fake *FakeRodeClient) EvaluatePolicy(arg1 context.Context, arg2 *v1alpha1.EvaluatePolicyRequest, arg3 ...grpc.CallOption) (*v1alpha1.EvaluatePolicyResponse, error) {
	fake.evaluatePolicyMutex.Lock()
	ret, specificReturn := fake.evaluatePolicyReturnsOnCall[len(fake.evaluatePolicyArgsForCall)]
	fake.evaluatePolicyArgsForCall = append(fake.evaluatePolicyArgsForCall, struct {
		arg1 context.Context
		arg2 *v1alpha1.EvaluatePolicyRequest
		arg3 []grpc.CallOption
	}{arg1, arg2, arg3})
	stub := fake.EvaluatePolicyStub
	fakeReturns := fake.evaluatePolicyReturns
	fake.recordInvocation("EvaluatePolicy", []interface{}{arg1, arg2, arg3})
	fake.evaluatePolicyMutex.Unlock()
	if stub != nil {
		return stub(arg1, arg2, arg3...)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *FakeRodeClient) EvaluatePolicyCallCount() int {
	fake.evaluatePolicyMutex.RLock()
	defer fake.evaluatePolicyMutex.RUnlock()
	return len(fake.evaluatePolicyArgsForCall)
}

func (fake *FakeRodeClient) EvaluatePolicyCalls(stub func(context.Context, *v1alpha1.EvaluatePolicyRequest, ...grpc.CallOption) (*v1alpha1.EvaluatePolicyResponse, error)) {
	fake.evaluatePolicyMutex.Lock()
	defer fake.evaluatePolicyMutex.Unlock()
	fake.EvaluatePolicyStub = stub
}

func (fake *FakeRodeClient) EvaluatePolicyArgsForCall(i int) (context.Context, *v1alpha1.EvaluatePolicyRequest, []grpc.CallOption) {
	fake.evaluatePolicyMutex.RLock()
	defer fake.evaluatePolicyMutex.RUnlock()
	argsForCall := fake.evaluatePolicyArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2, argsForCall.arg3
}

func (fake *FakeRodeClient) EvaluatePolicyReturns(result1 *v1alpha1.EvaluatePolicyResponse, result2 error) {
	fake.evaluatePolicyMutex.Lock()
	defer fake.evaluatePolicyMutex.Unlock()
	fake.EvaluatePolicyStub = nil
	fake.evaluatePolicyReturns = struct {
		result1 *v1alpha1.EvaluatePolicyResponse
		result2 error
	}{result1, result2}
}

func (fake *FakeRodeClient) EvaluatePolicyReturnsOnCall(i int, result1 *v1alpha1.EvaluatePolicyResponse, result2 error) {
	fake.evaluatePolicyMutex.Lock()
	defer fake.evaluatePolicyMutex.Unlock()
	fake.EvaluatePolicyStub = nil
	if fake.evaluatePolicyReturnsOnCall == nil {
		fake.evaluatePolicyReturnsOnCall = make(map[int]struct {
			result1 *v1alpha1.EvaluatePolicyResponse
			result2 error
		})
	}
	fake.evaluatePolicyReturnsOnCall[i] = struct {
		result1 *v1alpha1.EvaluatePolicyResponse
		result2 error
	}{result1, result2}
}

func (fake *FakeRodeClient) GetPolicy(arg1 context.Context, arg2 *v1alpha1.GetPolicyRequest, arg3 ...grpc.CallOption) (*v1alpha1.Policy, error) {
	fake.getPolicyMutex.Lock()
	ret, specificReturn := fake.getPolicyReturnsOnCall[len(fake.getPolicyArgsForCall)]
	fake.getPolicyArgsForCall = append(fake.getPolicyArgsForCall, struct {
		arg1 context.Context
		arg2 *v1alpha1.GetPolicyRequest
		arg3 []grpc.CallOption
	}{arg1, arg2, arg3})
	stub := fake.GetPolicyStub
	fakeReturns := fake.getPolicyReturns
	fake.recordInvocation("GetPolicy", []interface{}{arg1, arg2, arg3})
	fake.getPolicyMutex.Unlock()
	if stub != nil {
		return stub(arg1, arg2, arg3...)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *FakeRodeClient) GetPolicyCallCount() int {
	fake.getPolicyMutex.RLock()
	defer fake.getPolicyMutex.RUnlock()
	return len(fake.getPolicyArgsForCall)
}

func (fake *FakeRodeClient) GetPolicyCalls(stub func(context.Context, *v1alpha1.GetPolicyRequest, ...grpc.CallOption) (*v1alpha1.Policy, error)) {
	fake.getPolicyMutex.Lock()
	defer fake.getPolicyMutex.Unlock()
	fake.GetPolicyStub = stub
}

func (fake *FakeRodeClient) GetPolicyArgsForCall(i int) (context.Context, *v1alpha1.GetPolicyRequest, []grpc.CallOption) {
	fake.getPolicyMutex.RLock()
	defer fake.getPolicyMutex.RUnlock()
	argsForCall := fake.getPolicyArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2, argsForCall.arg3
}

func (fake *FakeRodeClient) GetPolicyReturns(result1 *v1alpha1.Policy, result2 error) {
	fake.getPolicyMutex.Lock()
	defer fake.getPolicyMutex.Unlock()
	fake.GetPolicyStub = nil
	fake.getPolicyReturns = struct {
		result1 *v1alpha1.Policy
		result2 error
	}{result1, result2}
}

func (fake *FakeRodeClient) GetPolicyReturnsOnCall(i int, result1 *v1alpha1.Policy, result2 error) {
	fake.getPolicyMutex.Lock()
	defer fake.getPolicyMutex.Unlock()
	fake.GetPolicyStub = nil
	if fake.getPolicyReturnsOnCall == nil {
		fake.getPolicyReturnsOnCall = make(map[int]struct {
			result1 *v1alpha1.Policy
			result2 error
		})
	}
	fake.getPolicyReturnsOnCall[i] = struct {
		result1 *v1alpha1.Policy
		result2 error
	}{result1, result2}
}

func (fake *FakeRodeClient) ListGenericResources(arg1 context.Context, arg2 *v1alpha1.ListGenericResourcesRequest, arg3 ...grpc.CallOption) (*v1alpha1.ListGenericResourcesResponse, error) {
	fake.listGenericResourcesMutex.Lock()
	ret, specificReturn := fake.listGenericResourcesReturnsOnCall[len(fake.listGenericResourcesArgsForCall)]
	fake.listGenericResourcesArgsForCall = append(fake.listGenericResourcesArgsForCall, struct {
		arg1 context.Context
		arg2 *v1alpha1.ListGenericResourcesRequest
		arg3 []grpc.CallOption
	}{arg1, arg2, arg3})
	stub := fake.ListGenericResourcesStub
	fakeReturns := fake.listGenericResourcesReturns
	fake.recordInvocation("ListGenericResources", []interface{}{arg1, arg2, arg3})
	fake.listGenericResourcesMutex.Unlock()
	if stub != nil {
		return stub(arg1, arg2, arg3...)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *FakeRodeClient) ListGenericResourcesCallCount() int {
	fake.listGenericResourcesMutex.RLock()
	defer fake.listGenericResourcesMutex.RUnlock()
	return len(fake.listGenericResourcesArgsForCall)
}

func (fake *FakeRodeClient) ListGenericResourcesCalls(stub func(context.Context, *v1alpha1.ListGenericResourcesRequest, ...grpc.CallOption) (*v1alpha1.ListGenericResourcesResponse, error)) {
	fake.listGenericResourcesMutex.Lock()
	defer fake.listGenericResourcesMutex.Unlock()
	fake.ListGenericResourcesStub = stub
}

func (fake *FakeRodeClient) ListGenericResourcesArgsForCall(i int) (context.Context, *v1alpha1.ListGenericResourcesRequest, []grpc.CallOption) {
	fake.listGenericResourcesMutex.RLock()
	defer fake.listGenericResourcesMutex.RUnlock()
	argsForCall := fake.listGenericResourcesArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2, argsForCall.arg3
}

func (fake *FakeRodeClient) ListGenericResourcesReturns(result1 *v1alpha1.ListGenericResourcesResponse, result2 error) {
	fake.listGenericResourcesMutex.Lock()
	defer fake.listGenericResourcesMutex.Unlock()
	fake.ListGenericResourcesStub = nil
	fake.listGenericResourcesReturns = struct {
		result1 *v1alpha1.ListGenericResourcesResponse
		result2 error
	}{result1, result2}
}

func (fake *FakeRodeClient) ListGenericResourcesReturnsOnCall(i int, result1 *v1alpha1.ListGenericResourcesResponse, result2 error) {
	fake.listGenericResourcesMutex.Lock()
	defer fake.listGenericResourcesMutex.Unlock()
	fake.ListGenericResourcesStub = nil
	if fake.listGenericResourcesReturnsOnCall == nil {
		fake.listGenericResourcesReturnsOnCall = make(map[int]struct {
			result1 *v1alpha1.ListGenericResourcesResponse
			result2 error
		})
	}
	fake.listGenericResourcesReturnsOnCall[i] = struct {
		result1 *v1alpha1.ListGenericResourcesResponse
		result2 error
	}{result1, result2}
}

func (fake *FakeRodeClient) ListOccurrences(arg1 context.Context, arg2 *v1alpha1.ListOccurrencesRequest, arg3 ...grpc.CallOption) (*v1alpha1.ListOccurrencesResponse, error) {
	fake.listOccurrencesMutex.Lock()
	ret, specificReturn := fake.listOccurrencesReturnsOnCall[len(fake.listOccurrencesArgsForCall)]
	fake.listOccurrencesArgsForCall = append(fake.listOccurrencesArgsForCall, struct {
		arg1 context.Context
		arg2 *v1alpha1.ListOccurrencesRequest
		arg3 []grpc.CallOption
	}{arg1, arg2, arg3})
	stub := fake.ListOccurrencesStub
	fakeReturns := fake.listOccurrencesReturns
	fake.recordInvocation("ListOccurrences", []interface{}{arg1, arg2, arg3})
	fake.listOccurrencesMutex.Unlock()
	if stub != nil {
		return stub(arg1, arg2, arg3...)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *FakeRodeClient) ListOccurrencesCallCount() int {
	fake.listOccurrencesMutex.RLock()
	defer fake.listOccurrencesMutex.RUnlock()
	return len(fake.listOccurrencesArgsForCall)
}

func (fake *FakeRodeClient) ListOccurrencesCalls(stub func(context.Context, *v1alpha1.ListOccurrencesRequest, ...grpc.CallOption) (*v1alpha1.ListOccurrencesResponse, error)) {
	fake.listOccurrencesMutex.Lock()
	defer fake.listOccurrencesMutex.Unlock()
	fake.ListOccurrencesStub = stub
}

func (fake *FakeRodeClient) ListOccurrencesArgsForCall(i int) (context.Context, *v1alpha1.ListOccurrencesRequest, []grpc.CallOption) {
	fake.listOccurrencesMutex.RLock()
	defer fake.listOccurrencesMutex.RUnlock()
	argsForCall := fake.listOccurrencesArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2, argsForCall.arg3
}

func (fake *FakeRodeClient) ListOccurrencesReturns(result1 *v1alpha1.ListOccurrencesResponse, result2 error) {
	fake.listOccurrencesMutex.Lock()
	defer fake.listOccurrencesMutex.Unlock()
	fake.ListOccurrencesStub = nil
	fake.listOccurrencesReturns = struct {
		result1 *v1alpha1.ListOccurrencesResponse
		result2 error
	}{result1, result2}
}

func (fake *FakeRodeClient) ListOccurrencesReturnsOnCall(i int, result1 *v1alpha1.ListOccurrencesResponse, result2 error) {
	fake.listOccurrencesMutex.Lock()
	defer fake.listOccurrencesMutex.Unlock()
	fake.ListOccurrencesStub = nil
	if fake.listOccurrencesReturnsOnCall == nil {
		fake.listOccurrencesReturnsOnCall = make(map[int]struct {
			result1 *v1alpha1.ListOccurrencesResponse
			result2 error
		})
	}
	fake.listOccurrencesReturnsOnCall[i] = struct {
		result1 *v1alpha1.ListOccurrencesResponse
		result2 error
	}{result1, result2}
}

func (fake *FakeRodeClient) ListPolicies(arg1 context.Context, arg2 *v1alpha1.ListPoliciesRequest, arg3 ...grpc.CallOption) (*v1alpha1.ListPoliciesResponse, error) {
	fake.listPoliciesMutex.Lock()
	ret, specificReturn := fake.listPoliciesReturnsOnCall[len(fake.listPoliciesArgsForCall)]
	fake.listPoliciesArgsForCall = append(fake.listPoliciesArgsForCall, struct {
		arg1 context.Context
		arg2 *v1alpha1.ListPoliciesRequest
		arg3 []grpc.CallOption
	}{arg1, arg2, arg3})
	stub := fake.ListPoliciesStub
	fakeReturns := fake.listPoliciesReturns
	fake.recordInvocation("ListPolicies", []interface{}{arg1, arg2, arg3})
	fake.listPoliciesMutex.Unlock()
	if stub != nil {
		return stub(arg1, arg2, arg3...)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *FakeRodeClient) ListPoliciesCallCount() int {
	fake.listPoliciesMutex.RLock()
	defer fake.listPoliciesMutex.RUnlock()
	return len(fake.listPoliciesArgsForCall)
}

func (fake *FakeRodeClient) ListPoliciesCalls(stub func(context.Context, *v1alpha1.ListPoliciesRequest, ...grpc.CallOption) (*v1alpha1.ListPoliciesResponse, error)) {
	fake.listPoliciesMutex.Lock()
	defer fake.listPoliciesMutex.Unlock()
	fake.ListPoliciesStub = stub
}

func (fake *FakeRodeClient) ListPoliciesArgsForCall(i int) (context.Context, *v1alpha1.ListPoliciesRequest, []grpc.CallOption) {
	fake.listPoliciesMutex.RLock()
	defer fake.listPoliciesMutex.RUnlock()
	argsForCall := fake.listPoliciesArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2, argsForCall.arg3
}

func (fake *FakeRodeClient) ListPoliciesReturns(result1 *v1alpha1.ListPoliciesResponse, result2 error) {
	fake.listPoliciesMutex.Lock()
	defer fake.listPoliciesMutex.Unlock()
	fake.ListPoliciesStub = nil
	fake.listPoliciesReturns = struct {
		result1 *v1alpha1.ListPoliciesResponse
		result2 error
	}{result1, result2}
}

func (fake *FakeRodeClient) ListPoliciesReturnsOnCall(i int, result1 *v1alpha1.ListPoliciesResponse, result2 error) {
	fake.listPoliciesMutex.Lock()
	defer fake.listPoliciesMutex.Unlock()
	fake.ListPoliciesStub = nil
	if fake.listPoliciesReturnsOnCall == nil {
		fake.listPoliciesReturnsOnCall = make(map[int]struct {
			result1 *v1alpha1.ListPoliciesResponse
			result2 error
		})
	}
	fake.listPoliciesReturnsOnCall[i] = struct {
		result1 *v1alpha1.ListPoliciesResponse
		result2 error
	}{result1, result2}
}

func (fake *FakeRodeClient) ListResources(arg1 context.Context, arg2 *v1alpha1.ListResourcesRequest, arg3 ...grpc.CallOption) (*v1alpha1.ListResourcesResponse, error) {
	fake.listResourcesMutex.Lock()
	ret, specificReturn := fake.listResourcesReturnsOnCall[len(fake.listResourcesArgsForCall)]
	fake.listResourcesArgsForCall = append(fake.listResourcesArgsForCall, struct {
		arg1 context.Context
		arg2 *v1alpha1.ListResourcesRequest
		arg3 []grpc.CallOption
	}{arg1, arg2, arg3})
	stub := fake.ListResourcesStub
	fakeReturns := fake.listResourcesReturns
	fake.recordInvocation("ListResources", []interface{}{arg1, arg2, arg3})
	fake.listResourcesMutex.Unlock()
	if stub != nil {
		return stub(arg1, arg2, arg3...)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *FakeRodeClient) ListResourcesCallCount() int {
	fake.listResourcesMutex.RLock()
	defer fake.listResourcesMutex.RUnlock()
	return len(fake.listResourcesArgsForCall)
}

func (fake *FakeRodeClient) ListResourcesCalls(stub func(context.Context, *v1alpha1.ListResourcesRequest, ...grpc.CallOption) (*v1alpha1.ListResourcesResponse, error)) {
	fake.listResourcesMutex.Lock()
	defer fake.listResourcesMutex.Unlock()
	fake.ListResourcesStub = stub
}

func (fake *FakeRodeClient) ListResourcesArgsForCall(i int) (context.Context, *v1alpha1.ListResourcesRequest, []grpc.CallOption) {
	fake.listResourcesMutex.RLock()
	defer fake.listResourcesMutex.RUnlock()
	argsForCall := fake.listResourcesArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2, argsForCall.arg3
}

func (fake *FakeRodeClient) ListResourcesReturns(result1 *v1alpha1.ListResourcesResponse, result2 error) {
	fake.listResourcesMutex.Lock()
	defer fake.listResourcesMutex.Unlock()
	fake.ListResourcesStub = nil
	fake.listResourcesReturns = struct {
		result1 *v1alpha1.ListResourcesResponse
		result2 error
	}{result1, result2}
}

func (fake *FakeRodeClient) ListResourcesReturnsOnCall(i int, result1 *v1alpha1.ListResourcesResponse, result2 error) {
	fake.listResourcesMutex.Lock()
	defer fake.listResourcesMutex.Unlock()
	fake.ListResourcesStub = nil
	if fake.listResourcesReturnsOnCall == nil {
		fake.listResourcesReturnsOnCall = make(map[int]struct {
			result1 *v1alpha1.ListResourcesResponse
			result2 error
		})
	}
	fake.listResourcesReturnsOnCall[i] = struct {
		result1 *v1alpha1.ListResourcesResponse
		result2 error
	}{result1, result2}
}

func (fake *FakeRodeClient) UpdateOccurrence(arg1 context.Context, arg2 *v1alpha1.UpdateOccurrenceRequest, arg3 ...grpc.CallOption) (*grafeas_go_proto.Occurrence, error) {
	fake.updateOccurrenceMutex.Lock()
	ret, specificReturn := fake.updateOccurrenceReturnsOnCall[len(fake.updateOccurrenceArgsForCall)]
	fake.updateOccurrenceArgsForCall = append(fake.updateOccurrenceArgsForCall, struct {
		arg1 context.Context
		arg2 *v1alpha1.UpdateOccurrenceRequest
		arg3 []grpc.CallOption
	}{arg1, arg2, arg3})
	stub := fake.UpdateOccurrenceStub
	fakeReturns := fake.updateOccurrenceReturns
	fake.recordInvocation("UpdateOccurrence", []interface{}{arg1, arg2, arg3})
	fake.updateOccurrenceMutex.Unlock()
	if stub != nil {
		return stub(arg1, arg2, arg3...)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *FakeRodeClient) UpdateOccurrenceCallCount() int {
	fake.updateOccurrenceMutex.RLock()
	defer fake.updateOccurrenceMutex.RUnlock()
	return len(fake.updateOccurrenceArgsForCall)
}

func (fake *FakeRodeClient) UpdateOccurrenceCalls(stub func(context.Context, *v1alpha1.UpdateOccurrenceRequest, ...grpc.CallOption) (*grafeas_go_proto.Occurrence, error)) {
	fake.updateOccurrenceMutex.Lock()
	defer fake.updateOccurrenceMutex.Unlock()
	fake.UpdateOccurrenceStub = stub
}

func (fake *FakeRodeClient) UpdateOccurrenceArgsForCall(i int) (context.Context, *v1alpha1.UpdateOccurrenceRequest, []grpc.CallOption) {
	fake.updateOccurrenceMutex.RLock()
	defer fake.updateOccurrenceMutex.RUnlock()
	argsForCall := fake.updateOccurrenceArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2, argsForCall.arg3
}

func (fake *FakeRodeClient) UpdateOccurrenceReturns(result1 *grafeas_go_proto.Occurrence, result2 error) {
	fake.updateOccurrenceMutex.Lock()
	defer fake.updateOccurrenceMutex.Unlock()
	fake.UpdateOccurrenceStub = nil
	fake.updateOccurrenceReturns = struct {
		result1 *grafeas_go_proto.Occurrence
		result2 error
	}{result1, result2}
}

func (fake *FakeRodeClient) UpdateOccurrenceReturnsOnCall(i int, result1 *grafeas_go_proto.Occurrence, result2 error) {
	fake.updateOccurrenceMutex.Lock()
	defer fake.updateOccurrenceMutex.Unlock()
	fake.UpdateOccurrenceStub = nil
	if fake.updateOccurrenceReturnsOnCall == nil {
		fake.updateOccurrenceReturnsOnCall = make(map[int]struct {
			result1 *grafeas_go_proto.Occurrence
			result2 error
		})
	}
	fake.updateOccurrenceReturnsOnCall[i] = struct {
		result1 *grafeas_go_proto.Occurrence
		result2 error
	}{result1, result2}
}

func (fake *FakeRodeClient) UpdatePolicy(arg1 context.Context, arg2 *v1alpha1.UpdatePolicyRequest, arg3 ...grpc.CallOption) (*v1alpha1.Policy, error) {
	fake.updatePolicyMutex.Lock()
	ret, specificReturn := fake.updatePolicyReturnsOnCall[len(fake.updatePolicyArgsForCall)]
	fake.updatePolicyArgsForCall = append(fake.updatePolicyArgsForCall, struct {
		arg1 context.Context
		arg2 *v1alpha1.UpdatePolicyRequest
		arg3 []grpc.CallOption
	}{arg1, arg2, arg3})
	stub := fake.UpdatePolicyStub
	fakeReturns := fake.updatePolicyReturns
	fake.recordInvocation("UpdatePolicy", []interface{}{arg1, arg2, arg3})
	fake.updatePolicyMutex.Unlock()
	if stub != nil {
		return stub(arg1, arg2, arg3...)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *FakeRodeClient) UpdatePolicyCallCount() int {
	fake.updatePolicyMutex.RLock()
	defer fake.updatePolicyMutex.RUnlock()
	return len(fake.updatePolicyArgsForCall)
}

func (fake *FakeRodeClient) UpdatePolicyCalls(stub func(context.Context, *v1alpha1.UpdatePolicyRequest, ...grpc.CallOption) (*v1alpha1.Policy, error)) {
	fake.updatePolicyMutex.Lock()
	defer fake.updatePolicyMutex.Unlock()
	fake.UpdatePolicyStub = stub
}

func (fake *FakeRodeClient) UpdatePolicyArgsForCall(i int) (context.Context, *v1alpha1.UpdatePolicyRequest, []grpc.CallOption) {
	fake.updatePolicyMutex.RLock()
	defer fake.updatePolicyMutex.RUnlock()
	argsForCall := fake.updatePolicyArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2, argsForCall.arg3
}

func (fake *FakeRodeClient) UpdatePolicyReturns(result1 *v1alpha1.Policy, result2 error) {
	fake.updatePolicyMutex.Lock()
	defer fake.updatePolicyMutex.Unlock()
	fake.UpdatePolicyStub = nil
	fake.updatePolicyReturns = struct {
		result1 *v1alpha1.Policy
		result2 error
	}{result1, result2}
}

func (fake *FakeRodeClient) UpdatePolicyReturnsOnCall(i int, result1 *v1alpha1.Policy, result2 error) {
	fake.updatePolicyMutex.Lock()
	defer fake.updatePolicyMutex.Unlock()
	fake.UpdatePolicyStub = nil
	if fake.updatePolicyReturnsOnCall == nil {
		fake.updatePolicyReturnsOnCall = make(map[int]struct {
			result1 *v1alpha1.Policy
			result2 error
		})
	}
	fake.updatePolicyReturnsOnCall[i] = struct {
		result1 *v1alpha1.Policy
		result2 error
	}{result1, result2}
}

func (fake *FakeRodeClient) ValidatePolicy(arg1 context.Context, arg2 *v1alpha1.ValidatePolicyRequest, arg3 ...grpc.CallOption) (*v1alpha1.ValidatePolicyResponse, error) {
	fake.validatePolicyMutex.Lock()
	ret, specificReturn := fake.validatePolicyReturnsOnCall[len(fake.validatePolicyArgsForCall)]
	fake.validatePolicyArgsForCall = append(fake.validatePolicyArgsForCall, struct {
		arg1 context.Context
		arg2 *v1alpha1.ValidatePolicyRequest
		arg3 []grpc.CallOption
	}{arg1, arg2, arg3})
	stub := fake.ValidatePolicyStub
	fakeReturns := fake.validatePolicyReturns
	fake.recordInvocation("ValidatePolicy", []interface{}{arg1, arg2, arg3})
	fake.validatePolicyMutex.Unlock()
	if stub != nil {
		return stub(arg1, arg2, arg3...)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *FakeRodeClient) ValidatePolicyCallCount() int {
	fake.validatePolicyMutex.RLock()
	defer fake.validatePolicyMutex.RUnlock()
	return len(fake.validatePolicyArgsForCall)
}

func (fake *FakeRodeClient) ValidatePolicyCalls(stub func(context.Context, *v1alpha1.ValidatePolicyRequest, ...grpc.CallOption) (*v1alpha1.ValidatePolicyResponse, error)) {
	fake.validatePolicyMutex.Lock()
	defer fake.validatePolicyMutex.Unlock()
	fake.ValidatePolicyStub = stub
}

func (fake *FakeRodeClient) ValidatePolicyArgsForCall(i int) (context.Context, *v1alpha1.ValidatePolicyRequest, []grpc.CallOption) {
	fake.validatePolicyMutex.RLock()
	defer fake.validatePolicyMutex.RUnlock()
	argsForCall := fake.validatePolicyArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2, argsForCall.arg3
}

func (fake *FakeRodeClient) ValidatePolicyReturns(result1 *v1alpha1.ValidatePolicyResponse, result2 error) {
	fake.validatePolicyMutex.Lock()
	defer fake.validatePolicyMutex.Unlock()
	fake.ValidatePolicyStub = nil
	fake.validatePolicyReturns = struct {
		result1 *v1alpha1.ValidatePolicyResponse
		result2 error
	}{result1, result2}
}

func (fake *FakeRodeClient) ValidatePolicyReturnsOnCall(i int, result1 *v1alpha1.ValidatePolicyResponse, result2 error) {
	fake.validatePolicyMutex.Lock()
	defer fake.validatePolicyMutex.Unlock()
	fake.ValidatePolicyStub = nil
	if fake.validatePolicyReturnsOnCall == nil {
		fake.validatePolicyReturnsOnCall = make(map[int]struct {
			result1 *v1alpha1.ValidatePolicyResponse
			result2 error
		})
	}
	fake.validatePolicyReturnsOnCall[i] = struct {
		result1 *v1alpha1.ValidatePolicyResponse
		result2 error
	}{result1, result2}
}

func (fake *FakeRodeClient) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.batchCreateOccurrencesMutex.RLock()
	defer fake.batchCreateOccurrencesMutex.RUnlock()
	fake.createPolicyMutex.RLock()
	defer fake.createPolicyMutex.RUnlock()
	fake.deletePolicyMutex.RLock()
	defer fake.deletePolicyMutex.RUnlock()
	fake.evaluatePolicyMutex.RLock()
	defer fake.evaluatePolicyMutex.RUnlock()
	fake.getPolicyMutex.RLock()
	defer fake.getPolicyMutex.RUnlock()
	fake.listGenericResourcesMutex.RLock()
	defer fake.listGenericResourcesMutex.RUnlock()
	fake.listOccurrencesMutex.RLock()
	defer fake.listOccurrencesMutex.RUnlock()
	fake.listPoliciesMutex.RLock()
	defer fake.listPoliciesMutex.RUnlock()
	fake.listResourcesMutex.RLock()
	defer fake.listResourcesMutex.RUnlock()
	fake.updateOccurrenceMutex.RLock()
	defer fake.updateOccurrenceMutex.RUnlock()
	fake.updatePolicyMutex.RLock()
	defer fake.updatePolicyMutex.RUnlock()
	fake.validatePolicyMutex.RLock()
	defer fake.validatePolicyMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *FakeRodeClient) recordInvocation(key string, args []interface{}) {
	fake.invocationsMutex.Lock()
	defer fake.invocationsMutex.Unlock()
	if fake.invocations == nil {
		fake.invocations = map[string][][]interface{}{}
	}
	if fake.invocations[key] == nil {
		fake.invocations[key] = [][]interface{}{}
	}
	fake.invocations[key] = append(fake.invocations[key], args)
}

var _ v1alpha1.RodeClient = new(FakeRodeClient)