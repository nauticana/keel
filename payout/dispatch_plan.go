package payout

type dispatchPlan struct {
	instr    *Instruction
	leg      InstructionLeg
	provider PayoutProvider
}
