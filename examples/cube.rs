use ark_ff::Field;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError},
};
use ark_bls12_381::{Bls12_381, Fr as BlsFr};
use ark_groth16::Groth16;
use ark_snark::SNARK;
use rand_core::{OsRng};


// verifier wants to prove that she knows some x such that x^3 + x + 5 == 35
// or more general x^3 + x + 5 == (a public value)
struct CubeCircuit<F: Field> {
    pub x: Option<F>,
    pub out: Option<F>
}

impl<F: Field> ConstraintSynthesizer<F> for CubeCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
       
       // Flattened into quadratic equations (x^3 + x + 5 == 35): 
        // x * x = s1
        // s1 * x = s2
        // s2 + x = s3
        // s3 + 5 = out
        // Resulting R1CS with w = [one, x, s1, s2, s3, out]

        // allocate witness x
        let x_val = self.x;
        let x = cs.new_witness_variable(|| x_val.ok_or(SynthesisError::AssignmentMissing))?;

       // Allocate: x * x = s1
        let s1_val = x_val.map(|e| e.square());
        let s1 =
            cs.new_witness_variable(|| s1_val.ok_or(SynthesisError::AssignmentMissing))?;
          // Enforce: x * x = s1
        cs.enforce_constraint(
            lc!() + x, 
            lc!() + x, 
            lc!() + s1
        )?;

         // Allocate: s1 * x = s2
        let s2_val = s1_val.map(|mut e| {
            e.mul_assign(&x_val.unwrap());
            e
        });
        let s2 =
            cs.new_witness_variable(|| s2_val.ok_or(SynthesisError::AssignmentMissing))?;
        // Allocate: s2 + x = s3
        cs.enforce_constraint(
            lc!() + x, 
            lc!() + s1, 
            lc!() + s2
        )?;

        // Allocate: s2 + x = s3
        let s3_val = s2_val.map(|mut e| {
             e.add_assign(&x_val.unwrap());
            e
        });

        let s3 = cs.new_witness_variable(|| {
            s3_val.ok_or(SynthesisError::AssignmentMissing)
        })?;

        cs.enforce_constraint(
            lc!() + s2 + x, 
            lc!() + ConstraintSystem::<F>::one(), 
            lc!() + s3
        )?;


        let out_val = self.out;
        let out = cs.new_input_variable(|| {
            out_val.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Enforce: s3 + 5 = out
        cs.enforce_constraint(
            lc!() + s3 + (F::from(5u32), ConstraintSystem::<F>::one()),
            lc!() + ConstraintSystem::<F>::one(),
            lc!() + out
        )?;

        Ok(())
    }
}


fn main(){
    
}


#[test]
fn test_groth16_circuit_cube() {
    let rng = &mut OsRng;

    // generate the setup parameters
    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(
        CubeCircuit::<BlsFr> { x: None, out: None },
        rng,
    )
    .unwrap();

    // calculate the proof by passing witness variable value
    let proof1 = Groth16::<Bls12_381>::prove(
        &pk,
        CubeCircuit::<BlsFr> {
            x: Some(BlsFr::from(3)),
            out: Some(BlsFr::from(35)),
        },
        rng,
    )
    .unwrap();

    // validate the proof
    assert!(Groth16::<Bls12_381>::verify(&vk, &[BlsFr::from(35)], &proof1).unwrap());

    // calculate the proof by passing witness variable value
    let proof2 = Groth16::<Bls12_381>::prove(
        &pk,
        CubeCircuit::<BlsFr> {
            x: Some(BlsFr::from(4)),
            out: Some(BlsFr::from(73)),
        },
        rng,
    )
    .unwrap();
    
    assert!(Groth16::<Bls12_381>::verify(&vk, &[BlsFr::from(73)], &proof2).unwrap());

    assert!(!Groth16::<Bls12_381>::verify(&vk, &[BlsFr::from(35)], &proof2).unwrap());
    assert!(!Groth16::<Bls12_381>::verify(&vk, &[BlsFr::from(73)], &proof1).unwrap());
}

