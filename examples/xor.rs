
use ark_ff::Field;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError},
};
use ark_bls12_381::{Bls12_381, Fr as BlsFr};
use ark_groth16::Groth16;
use ark_snark::SNARK;
use rand_core::{OsRng};


pub struct BitXORGeneratorCircuit<F:Field> {
    pub a: Option<F>,
    pub b: Option<F>,
    pub c: Option<F>,
}

impl<F: Field> ConstraintSynthesizer<F> for BitXORGeneratorCircuit<F> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<F>,
    ) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| self.c.ok_or(SynthesisError::AssignmentMissing))?;

        let one = ConstraintSystem::<F>::one();
        // let zero = ConstraintSystem::<F>::zero();

        // check (1-a) * a = 0
        cs.enforce_constraint(
            lc!() + one - a,
            lc!() + a,
            lc!(),
        )?;

        // check (1-b) * b = 0
        cs.enforce_constraint(
            lc!() + one - b,
            lc!() + b,
            lc!(),
        )?;

        //calculate a xor b 
        cs.enforce_constraint(
            lc!() + one - c,
            lc!() + c,
            lc!(),
        )?;

        // check (1-b) * b = 0
        cs.enforce_constraint(
            lc!() + a + a,
            lc!() + b,
            lc!() + a + b -c,
        )?;
        
        Ok(())
    }
}

fn main(){

}

#[test]
//TODO(keep), test_bitxor_generator_success not verified yet
fn test_bitxor_generator_success(){
    let rng = &mut OsRng;

    // generate the setup parameters
    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(
        BitXORGeneratorCircuit::<BlsFr> { a: None, b: None, c:None},
        rng,
    ).unwrap();

    
    let a = BlsFr::from(1); 
    let b = BlsFr::from(1); 
    let c = BlsFr::from(0); 

    let proof = Groth16::<Bls12_381>::prove(
        &pk,
        BitXORGeneratorCircuit::<BlsFr> {
            a: Some(a),
            b: Some(b),
            c: Some(c),
        },
        rng,
    ).unwrap();

    assert!(Groth16::<Bls12_381>::verify(&vk, &[c], &proof).unwrap());
}

