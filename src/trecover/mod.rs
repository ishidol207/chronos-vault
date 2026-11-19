// tshare를 잃어버린 참여자는 auxinfo도 잃어버렸다고 보는게 타당
// 따라서 trecover를 실행하기 전에 모든 참여자가 auxinfo를 다시 실행해야 함

pub mod commit;
pub(crate) mod input;
pub mod participant;
mod recovery_data;
