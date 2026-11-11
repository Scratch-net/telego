package middleend

// Production path: marshal into a frame buffer, then frame and encrypt it in
// place.
func benchmarkRequestSubmission(request ProxyRequest) (LinkSubmission, error) {
	frame, payload, err := request.marshalFrame()
	if err != nil {
		return LinkSubmission{}, err
	}
	return LinkSubmission{SubmissionID: 1, ConnectionID: request.ConnectionID, Payload: payload, frame: frame}, nil
}

func benchmarkEncodeSubmission(client *ClientBootstrap, submission LinkSubmission) ([]byte, error) {
	return client.encodeSubmission(submission)
}
