//! This example shows how to use the Albert model to detect anomalous system calls
use std::{
    path::{Path, PathBuf},
    str::FromStr,
};
use tokenizers::tokenizer::{Result, Tokenizer};
use tract_onnx::prelude::*;

fn main() -> Result<()> {
    println!("Loading tokenizer Start...");
    let model_dir = PathBuf::from_str("./models/albert")?;
    let tokenizer = Tokenizer::from_file(Path::join(&model_dir, "tokenizer.json"))?;
    println!("Loading tokenizer End...");

    // Suppose system_calls is a Vec<u32> that represents your sequence of system calls
    let system_calls: Vec<u32> = vec![
        59, 12, 158, 9, 21, 257, 262, 257, 262, 257, 262, 257, 262, 257, 262, 257, 262, 257, 262,
        257, 262, 257, 262, 257, 262, 257, 262, 257, 262, 257, 262, 257, 262, 257, 262, 257, 262,
        257, 262, 257, 262, 257, 262, 257, 262, 257,
    ];

    // Convert to string and tokenize
    println!("Tokenization Start...");
    let system_calls_str = system_calls
        .into_iter()
        .map(|call| call.to_string())
        .collect::<Vec<String>>()
        .join(" ");
    let tokenizer_output = tokenizer.encode(system_calls_str, true)?;
    let input_ids = tokenizer_output.get_ids();
    let attention_mask = tokenizer_output.get_attention_mask();
    let length = input_ids.len();
    println!("Tokenization End.");

    println!("Loading model Start...");
    let model = tract_onnx::onnx()
        .model_for_path(Path::join(&model_dir, "model.onnx"))?
        .into_optimized()?
        .into_runnable()?;
    println!("Loading model End.");

    println!("Preprocessing Start...");
    let input_ids: Tensor = tract_ndarray::Array2::from_shape_vec(
        (1, length),
        input_ids.iter().map(|&x| x as i64).collect(),
    )?
    .into();
    let attention_mask: Tensor = tract_ndarray::Array2::from_shape_vec(
        (1, length),
        attention_mask.iter().map(|&x| x as i64).collect(),
    )?
    .into();
    println!("Preprocessing End.");

    println!("Inference Start...");
    let outputs = model.run(tvec!(input_ids.into(), attention_mask.into()))?;
    let logits = outputs[0].to_array_view::<f32>()?;
    let score = logits[[0, 1]].exp() / (logits[[0, 0]].exp() + logits[[0, 1]].exp()); // Compute softmax to get probability
    println!("Inference End.");

    // You might want to adjust the threshold depending on your use case
    let threshold = 0.5;
    if score > threshold {
        println!("The sequence of system calls is anomalous.");
    } else {
        println!("The sequence of system calls is normal.");
    }

    Ok(())
}
