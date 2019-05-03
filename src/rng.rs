extern crate amcl;
extern crate rand;

use rand::Rng;

use self::amcl::rand::RAND;

pub fn get_seeded_rng<R: Rng + ?Sized>(rng: &mut R, entropy_size: usize) -> RAND {
    // Generate entropy to seed the RNG
    let mut entropy = vec![0; entropy_size];
    rng.fill_bytes(&mut entropy.as_mut_slice());

    // Create the amcl RNG
    let mut rng = RAND::new();
    rng.clean();
    rng.seed(entropy_size, &entropy);
    rng
}
