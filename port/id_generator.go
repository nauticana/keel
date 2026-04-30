package port

// Generate a bigint GUID key
type BigintGenerator interface {
	NextID() int64
}
