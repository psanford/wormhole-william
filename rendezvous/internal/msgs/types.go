package msgs

type RendezvousType interface {
	GetType() string
}

type RendezvousID interface {
	GetID() string
}

type TypeAndID interface {
	RendezvousType
	RendezvousID
}
