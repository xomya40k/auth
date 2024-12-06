// Code generated by mockery v3.0.0-alpha.0. DO NOT EDIT.

package mocks

import mock "github.com/stretchr/testify/mock"

// EmailSender is an autogenerated mock type for the EmailSender type
type EmailSender struct {
	mock.Mock
}

// SendIpWarnig provides a mock function with given fields: to, ip
func (_m *EmailSender) SendIpWarnig(to string, ip string) error {
	ret := _m.Called(to, ip)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, string) error); ok {
		r0 = rf(to, ip)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

type mockConstructorTestingTNewEmailSender interface {
	mock.TestingT
	Cleanup(func())
}

// NewEmailSender creates a new instance of EmailSender. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewEmailSender(t mockConstructorTestingTNewEmailSender) *EmailSender {
	mock := &EmailSender{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
