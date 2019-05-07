use amcl_utils::FP2;

// Raise base to the power of (p^2 - 9) / 16
pub fn sqrt_division_chain(base: &FP2) -> FP2 {
    let mut tmp1: FP2;
    let mut tmp2: FP2;
    let mut tmp3: FP2;
    let mut tmp4: FP2;
    let mut tmp5: FP2;
    let mut tmp6: FP2;
    let mut tmp7: FP2;
    let mut tmp8: FP2;
    let mut tmp9: FP2;
    let mut tmp10: FP2;
    let mut tmp11: FP2;
    let mut tmp12: FP2;
    let mut tmp13: FP2;
    let mut tmp14: FP2;
    let mut tmp15: FP2;
    let mut tmp16: FP2;

    tmp1 = base.clone();
    tmp1.sqr(); // ^2
    tmp2 = tmp1.clone();
    tmp2.mul(&base); // ^3
    tmp15 = tmp1.clone();
    tmp15.mul(&tmp2); // ^5
    tmp3 = tmp1.clone();
    tmp3.mul(&tmp15); // ^7
    tmp14 = tmp1.clone();
    tmp14.mul(&tmp3); //^9
    tmp13 = tmp1.clone();
    tmp13.mul(&tmp14); // ^11
    tmp5 = tmp1.clone();
    tmp5.mul(&tmp13); // ^13
    tmp10 = tmp1.clone();
    tmp10.mul(&tmp5); // ^15
    tmp9 = tmp1.clone();
    tmp9.mul(&tmp10); // ^17
    tmp16 = tmp1.clone();
    tmp16.mul(&tmp9); // ^19
    tmp4 = tmp1.clone();
    tmp4.mul(&tmp16); // ^21
    tmp7 = tmp1.clone();
    tmp7.mul(&tmp4); // ^23
    tmp6 = tmp1.clone();
    tmp6.mul(&tmp7); // ^25
    tmp12 = tmp1.clone();
    tmp12.mul(&tmp6); // ^27
    tmp8 = tmp1.clone();
    tmp8.mul(&tmp12); // ^29
    tmp11 = tmp1.clone();
    tmp11.mul(&tmp8); // ^31

    tmp1 = tmp4.clone(); // ^21
    for _ in 0..3 {
        tmp1.sqr();
    } // ^168
    tmp1.mul(&base); // ^169
    for _ in 0..9 {
        tmp1.sqr();
    } // ^86528
    tmp1.mul(&tmp12); // ^86555
    for _ in 0..4 {
        tmp1.sqr();
    } // ^1384880
    tmp1.mul(&tmp5); // ^1384893
    for _ in 0..6 {
        tmp1.sqr();
    } // ^88633152
    tmp1.mul(&tmp14); // ^88633161
    for _ in 0..4 {
        tmp1.sqr();
    } // ^1418130576
    tmp1.mul(&tmp3); // ^1418130583
    for _ in 0..5 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp2); // ^
    for _ in 0..8 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp5); // ^
    for _ in 0..4 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp3); // ^
    for _ in 0..4 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp10); // ^
    for _ in 0..8 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp8); // ^
    for _ in 0..6 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp13); // ^
    for _ in 0..4 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp5); // ^
    for _ in 0..3 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&base); // ^
    for _ in 0..6 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp10); // ^
    for _ in 0..8 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp8); // ^
    for _ in 0..6 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp4); // ^
    for _ in 0..8 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp9); // ^
    for _ in 0..5 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp10); // ^
    for _ in 0..6 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp14); // ^
    for _ in 0..5 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp10); // ^
    for _ in 0..2 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&base); // ^
    for _ in 0..6 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp10); // ^
    for _ in 0..7 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp13); // ^
    for _ in 0..4 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp3); // ^
    for _ in 0..6 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp14); // ^
    for _ in 0..7 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp3); // ^
    for _ in 0..5 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp15); // ^
    for _ in 0..7 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp3); // ^
    for _ in 0..5 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp3); // ^
    for _ in 0..10 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp9); // ^
    for _ in 0..3 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp15); // ^
    for _ in 0..5 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp5); // ^
    for _ in 0..8 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp6); // ^
    for _ in 0..5 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp7); // ^
    for _ in 0..6 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp13); // ^
    for _ in 0..6 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp10); // ^
    for _ in 0..6 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp14); // ^
    for _ in 0..7 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp16); // ^
    for _ in 0..5 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp14); // ^
    for _ in 0..6 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp10); // ^
    for _ in 0..6 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp9); // ^
    for _ in 0..5 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp10); // ^
    for _ in 0..2 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&base); // ^
    for _ in 0..8 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp15); // ^
    for _ in 0..7 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp15); // ^
    for _ in 0..4 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp2); // ^
    for _ in 0..7 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp13); // ^
    for _ in 0..6 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp10); // ^
    for _ in 0..4 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp5); // ^
    for _ in 0..7 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp13); // ^
    for _ in 0..6 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp12); // ^
    for _ in 0..5 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp7); // ^
    for _ in 0..5 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp15); // ^
    for _ in 0..7 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp12); // ^
    for _ in 0..5 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp7); // ^
    for _ in 0..5 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp4); // ^
    for _ in 0..4 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp2); // ^
    for _ in 0..6 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp15); // ^
    for _ in 0..6 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp14); // ^
    for _ in 0..4 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp2); // ^
    for _ in 0..4 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp2); // ^
    for _ in 0..8 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp14); // ^
    for _ in 0..5 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp10); // ^
    for _ in 0..6 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp3); // ^
    for _ in 0..5 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp10); // ^
    for _ in 0..12 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp9); // ^
    for _ in 0..4 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp5); // ^
    for _ in 0..5 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp5); // ^
    for _ in 0..6 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp2); // ^
    for _ in 0..9 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp6); // ^
    for _ in 0..5 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp6); // ^
    for _ in 0..6 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp2); // ^
    for _ in 0..6 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp2); // ^
    for _ in 0..9 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp7); // ^
    for _ in 0..7 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp10); // ^
    for _ in 0..6 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp6); // ^
    for _ in 0..5 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp14); // ^
    for _ in 0..7 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp7); // ^
    for _ in 0..2 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&base); // ^
    for _ in 0..8 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp13); // ^
    for _ in 0..4 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp15); // ^
    for _ in 0..7 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp3); // ^
    for _ in 0..8 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp14); // ^
    for _ in 0..7 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp5); // ^
    for _ in 0..10 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp14); // ^
    for _ in 0..6 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp13); // ^
    for _ in 0..6 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp5); // ^
    for _ in 0..6 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp11); // ^
    for _ in 0..5 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp6); // ^
    for _ in 0..7 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp10); // ^
    for _ in 0..5 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp5); // ^
    for _ in 0..7 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp11); // ^
    for _ in 0..5 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp3); // ^
    for _ in 0..8 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp12); // ^
    for _ in 0..6 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp8); // ^
    for _ in 0..6 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp2); // ^
    for _ in 0..7 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp13); // ^
    for _ in 0..7 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp13); // ^
    for _ in 0..6 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp2); // ^
    for _ in 0..5 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp3); // ^
    for _ in 0..10 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp12); // ^
    for _ in 0..4 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&base); // ^
    for _ in 0..9 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp9); // ^
    for _ in 0..6 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp10); // ^
    for _ in 0..7 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp11); // ^
    for _ in 0..5 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp4); // ^
    for _ in 0..4 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp10); // ^
    for _ in 0..7 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp8); // ^
    for _ in 0..5 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp4); // ^
    for _ in 0..5 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp4); // ^
    for _ in 0..5 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp9); // ^
    for _ in 0..4 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp5); // ^
    for _ in 0..6 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp8); // ^
    tmp1.sqr(); // ^
    tmp1.mul(&base); // ^
    for _ in 0..6 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp3); // ^
    for _ in 0..10 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp7); // ^
    for _ in 0..6 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp4); // ^
    for _ in 0..6 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp6); // ^
    for _ in 0..6 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp5); // ^
    for _ in 0..6 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp4); // ^
    for _ in 0..23 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp3); // ^
    for _ in 0..6 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp3); // ^
    for _ in 0..5 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp2); // ^
    for _ in 0..6 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp3); // ^
    for _ in 0..5 {
        tmp1.sqr();
    } // ^
    tmp1.mul(&tmp2); // ^1001205140483106588246484290269935788605945006208159541241399033561623546780709821462541004956387089373434649096260670658193992783731681621012512651314777238193313314641988297376025498093520728838658813979860931248214124593092835

    tmp1
}
