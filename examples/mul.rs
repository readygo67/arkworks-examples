use ark_ff::Field;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_bls12_381::{Bls12_381, Fr as BlsFr};
use ark_groth16::Groth16;
use ark_snark::SNARK;
use ark_std::rand::Rng;
use rand_core::{RngCore, OsRng};


// Multiplier circuit
// proving that I know a such that a * b = c
#[derive(Copy, Clone)]
pub struct MultiplierCircuit<F:Field> {
    pub a: Option<F>,
    pub b: Option<F>,
    pub c: Option<F>
}

pub struct MultiplierGeneratorCircuit<F:Field> {
    pub a: Option<F>,
    pub b: Option<F>,
}



impl<F: Field> ConstraintSynthesizer<F> for MultiplierCircuit<F> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<F>,
    ) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| self.c.ok_or(SynthesisError::AssignmentMissing))?;

        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;

        Ok(())
    }
}

impl<F: Field> ConstraintSynthesizer<F> for MultiplierGeneratorCircuit<F> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<F>,
    ) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| {
            let mut a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;
            a.mul_assign(&b);
            Ok(a)
        })?;

        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;

        Ok(())
    }
}

    
fn main() {
    let rng = &mut OsRng;

    // generate the setup parameters
    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(
        MultiplierCircuit::<BlsFr> { a: None, b: None, c :None },
        rng,
    )
    .unwrap();

    let a = BlsFr::from(4); 
    let b = BlsFr::from(5);
    let c = BlsFr::from(20);


    let proof = Groth16::<Bls12_381>::prove(
        &pk,
        MultiplierCircuit::<BlsFr> {
            a: Some(a),
            b: Some(b),
            c: Some(c),
        },
        rng,
    )
    .unwrap();

    assert!(Groth16::<Bls12_381>::verify(&vk, &[c], &proof).unwrap());
}


#[test]
fn test_multiplier_success() {
    let rng = &mut OsRng;

    // generate the setup parameters
    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(
        MultiplierCircuit::<BlsFr> { a: None, b: None, c:None },
        rng,
    )
    .unwrap();


    let a = BlsFr::from(4); 
    let b = BlsFr::from(5);
    let c = BlsFr::from(20);

    let proof = Groth16::<Bls12_381>::prove(
        &pk,
        MultiplierCircuit::<BlsFr> {
            a: Some(a),
            b: Some(b),
            c: Some(c),
        },
        rng,
    )
    .unwrap();

    assert!(Groth16::<Bls12_381>::verify(&vk, &[c], &proof).unwrap());
}


#[test]
fn test_multiplier_generator_success() {
    let rng = &mut OsRng;

    // generate the setup parameters
    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(
        MultiplierGeneratorCircuit::<BlsFr> { a: None, b: None},
        rng,
    )
    .unwrap();


    let a_val = rng.gen_range(1..100);
    let b_val = rng.gen_range(1..100);
    
    let a = BlsFr::from(a_val); 
    let b = BlsFr::from(b_val);

    let proof = Groth16::<Bls12_381>::prove(
        &pk,
        MultiplierGeneratorCircuit::<BlsFr> {
            a: Some(a),
            b: Some(b),
        },
        rng,
    )
    .unwrap();

    let c_val = a_val * b_val;
    let c = BlsFr::from(c_val);

    assert!(Groth16::<Bls12_381>::verify(&vk, &[c], &proof).unwrap());
}

